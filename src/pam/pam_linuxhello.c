/*
 * pam_linuxhello.c – PAM authentication module for LinuxHello
 *
 * PAM hooks implemented:
 *   pam_sm_authenticate  – main auth flow (challenge-response)
 *   pam_sm_setcred       – no-op (credentials managed by OS session)
 *   pam_sm_acct_mgmt     – checks whether user has enrolled credential
 *   pam_sm_open_session  – no-op
 *   pam_sm_close_session – no-op
 *   pam_sm_chauthtok     – no-op (PIN changes handled by lh-enroll)
 *
 * Authentication flow:
 *   1. Read username from PAM conversation
 *   2. Connect to the LinuxHello auth daemon via Unix domain socket
 *   3. Send LH_MSG_AUTH_REQUEST
 *   4. Receive LH_MSG_CHALLENGE (72-byte challenge)
 *   5. Prompt user for PIN (or inform user to place finger if biometric)
 *   6. Send PIN to daemon; daemon performs gesture gate + TPM signing
 *   7. Receive LH_MSG_AUTH_RESULT and map to PAM_SUCCESS / PAM_AUTH_ERR
 *
 * The PAM module itself has NO knowledge of keys, TPM, or biometrics.
 * All sensitive operations happen inside the privileged daemon (lhd).
 *
 * Compile:
 *   gcc -shared -fPIC -o pam_linuxhello.so pam_linuxhello.c \
 *       -lpam -Wall -Wextra -O2
 *
 * Install:
 *   cp pam_linuxhello.so /lib/$(uname -m)-linux-gnu/security/
 *
 * PAM stack snippet (e.g., /etc/pam.d/gdm-password):
 *   auth  sufficient  pam_linuxhello.so
 *   auth  required    pam_unix.so try_first_pass
 */

#define PAM_SM_AUTH
#define PAM_SM_ACCOUNT

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include <stdbool.h>
#include <syslog.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>

#include "../common/linuxhello.h"

/* ── Module option defaults ──────────────────────────────── */

#define LH_PAM_OPT_FALLBACK        "fallback"        /* allow password fallback      */
#define LH_PAM_OPT_NOFALLBACK      "nofallback"      /* no fallback (hardened mode)  */
#define LH_PAM_OPT_DEBUG           "debug"
#define LH_PAM_OPT_SKIP_SERVICE    "skip_on_service=" /* comma-separated service list */

/* Maximum number of service names that can be excluded */
#define LH_MAX_SKIP_SERVICES  16

typedef struct lh_pam_opts {
    bool  allow_fallback;
    bool  debug;
    /* Services for which LinuxHello PIN auth is silently skipped.
     * Typical use: skip_on_service=sudo,su-l,su,su
     * This allows pam_linuxhello to live in common-auth without
     * prompting for a PIN when the user runs sudo. */
    char  skip_services[LH_MAX_SKIP_SERVICES][64];
    int   skip_service_count;
} lh_pam_opts_t;

static void parse_opts(int argc, const char **argv, lh_pam_opts_t *o)
{
    o->allow_fallback      = true; /* default: fallback to password allowed */
    o->debug               = false;
    o->skip_service_count  = 0;

    for (int i = 0; i < argc; i++) {
        if (strcmp(argv[i], LH_PAM_OPT_NOFALLBACK) == 0)
            o->allow_fallback = false;
        else if (strcmp(argv[i], LH_PAM_OPT_DEBUG) == 0)
            o->debug = true;
        else if (strncmp(argv[i], LH_PAM_OPT_SKIP_SERVICE,
                         strlen(LH_PAM_OPT_SKIP_SERVICE)) == 0)
        {
            /* Parse comma-separated list after the '=' */
            const char *list = argv[i] + strlen(LH_PAM_OPT_SKIP_SERVICE);
            char buf[256];
            strncpy(buf, list, sizeof(buf) - 1);
            buf[sizeof(buf) - 1] = '\0';

            char *tok = strtok(buf, ",");
            while (tok && o->skip_service_count < LH_MAX_SKIP_SERVICES) {
                strncpy(o->skip_services[o->skip_service_count],
                        tok,
                        sizeof(o->skip_services[0]) - 1);
                o->skip_services[o->skip_service_count]
                    [sizeof(o->skip_services[0]) - 1] = '\0';
                o->skip_service_count++;
                tok = strtok(NULL, ",");
            }
        }
    }
}

/*
 * service_is_skipped – returns true if the PAM service name matches any
 * entry in the skip_services list.
 */
static bool service_is_skipped(pam_handle_t *pamh, const lh_pam_opts_t *o)
{
    if (o->skip_service_count == 0)
        return false;

    const char *svc = NULL;
    if (pam_get_item(pamh, PAM_SERVICE, (const void **)&svc) != PAM_SUCCESS
        || !svc)
        return false;

    for (int i = 0; i < o->skip_service_count; i++) {
        if (strcmp(svc, o->skip_services[i]) == 0)
            return true;
    }
    return false;
}

/* ── IPC helpers ─────────────────────────────────────────── */

static int connect_daemon(void)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, LH_DAEMON_SOCKET, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int send_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) return -1;
        p   += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int recv_all(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) return -1;
        p   += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

/* ── pam_sm_authenticate ─────────────────────────────────── */

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh,
                                    int           flags,
                                    int           argc,
                                    const char  **argv)
{
    lh_pam_opts_t opts;
    parse_opts(argc, argv, &opts);

    (void)flags;

    /* ── 1. Get username ────────────────────────────────────────── */
    const char *username = NULL;
    int pam_rc = pam_get_user(pamh, &username, "Username: ");
    if (pam_rc != PAM_SUCCESS || !username || !*username) {
        pam_syslog(pamh, LOG_ERR, "linuxhello: failed to get username");
        return opts.allow_fallback ? PAM_IGNORE : PAM_AUTH_ERR;
    }

    /*
     * ── 1a. Service exclusion check ────────────────────────────────
     *
     * When skip_on_service=sudo,su-l,... is configured, silently skip
     * LinuxHello for those PAM services so that 'sudo' continues to use
     * the standard password prompt without also asking for a PIN.
     */
    if (service_is_skipped(pamh, &opts)) {
        if (opts.debug) {
            const char *svc = NULL;
            pam_get_item(pamh, PAM_SERVICE, (const void **)&svc);
            pam_syslog(pamh, LOG_DEBUG,
                       "linuxhello: skipping for service '%s'",
                       svc ? svc : "(unknown)");
        }
        return PAM_IGNORE;
    }

    if (opts.debug)
        pam_syslog(pamh, LOG_DEBUG, "linuxhello: authenticating user %s",
                   username);

    /* ── 2. Connect to the auth daemon ──────────────────────────── */
    int daemon_fd = connect_daemon();
    if (daemon_fd < 0) {
        pam_syslog(pamh, LOG_WARNING,
                   "linuxhello: cannot reach auth daemon (%s): %s",
                   LH_DAEMON_SOCKET, strerror(errno));
        return opts.allow_fallback ? PAM_IGNORE : PAM_AUTHINFO_UNAVAIL;
    }

    /* ── 3. Send auth request ────────────────────────────────────── */
    lh_auth_request_t req;
    memset(&req, 0, sizeof(req));
    req.hdr.type   = LH_MSG_AUTH_REQUEST;
    req.hdr.length = (uint16_t)sizeof(req);
    strncpy(req.username, username, sizeof(req.username) - 1);

    if (send_all(daemon_fd, &req, sizeof(req)) != 0) {
        pam_syslog(pamh, LOG_ERR, "linuxhello: send auth request failed");
        close(daemon_fd);
        return opts.allow_fallback ? PAM_IGNORE : PAM_AUTH_ERR;
    }

    /* ── 4. Receive challenge ─────────────────────────────────────── */
    lh_challenge_msg_t chal;
    if (recv_all(daemon_fd, &chal, sizeof(chal)) != 0) {
        pam_syslog(pamh, LOG_ERR, "linuxhello: receive challenge failed");
        close(daemon_fd);
        return opts.allow_fallback ? PAM_IGNORE : PAM_AUTH_ERR;
    }

    if (chal.hdr.type == LH_MSG_AUTH_RESULT) {
        /* Daemon returned early (no credential enrolled or locked) */
        lh_auth_result_msg_t *early = (lh_auth_result_msg_t *)&chal;
        if (opts.debug)
            pam_syslog(pamh, LOG_DEBUG,
                       "linuxhello: early result %d for %s",
                       early->result, username);
        close(daemon_fd);
        if (early->result == LH_ERR_NO_CRED)
            return opts.allow_fallback ? PAM_IGNORE : PAM_USER_UNKNOWN;
        if (early->result == LH_ERR_LOCKED)
            return PAM_MAXTRIES;
        return opts.allow_fallback ? PAM_IGNORE : PAM_AUTH_ERR;
    }

    if (chal.hdr.type != LH_MSG_CHALLENGE) {
        pam_syslog(pamh, LOG_ERR,
                   "linuxhello: unexpected message type 0x%02x", chal.hdr.type);
        close(daemon_fd);
        return opts.allow_fallback ? PAM_IGNORE : PAM_AUTH_ERR;
    }

    /*
     * ── 5. Collect gesture (PIN or biometric) ──────────────────────
     *
     * The daemon already knows whether the user has a biometric enrolled.
     * If biometric is the gesture, the daemon drives fprintd internally
     * and we only need to send the PIN as empty (or not at all).
     * If PIN is the gesture, we prompt for it here.
     *
     * We always prompt for PIN as a fallback gesture even when biometric
     * is configured, per the Windows Hello model ("use PIN as backup").
     */
    const char *pin_token = NULL;
    struct pam_conv *conv = NULL;

    pam_get_item(pamh, PAM_CONV, (const void **)&conv);

    /*
     * First, attempt biometric (non-blocking notification to the daemon
     * is already triggered; biometric is driven daemon-side via fprintd).
     * Then prompt for PIN – the daemon accepts whichever comes first.
     */
    if (conv) {
        /*
         * Show a single prompt that accepts either the LinuxHello PIN or
         * nothing (empty Enter) to fall through to the next PAM module
         * (typically pam_unix password auth).  This gives the user a
         * Windows-Hello-like choice at the login screen:
         *   – type PIN  → LinuxHello authenticates
         *   – press Enter with no input → PAM_IGNORE sent, pam_unix
         *     continues and prompts for the account password
         *
         * For display managers (GDM, LightDM) the greeter must be
         * configured to show a second password field when LinuxHello
         * returns IGNORE; see pam.d/linuxhello for stack examples.
         */
        struct pam_message msg  = { PAM_PROMPT_ECHO_OFF,
                                    "PIN (empty = use password instead): " };
        const struct pam_message *msgp = &msg;
        struct pam_response *resp = NULL;

        if (conv->conv(1, &msgp, &resp, conv->appdata_ptr) == PAM_SUCCESS
            && resp && resp->resp)
        {
            pin_token = resp->resp; /* will be freed after use */
        }
    }

    /*
     * If the user submitted an empty response, treat it as "use password
     * instead": skip LinuxHello entirely so the next module (pam_unix)
     * handles authentication.
     */
    if (!pin_token || !*pin_token) {
        if (pin_token) {
            free((void *)pin_token);
            pin_token = NULL;
        }
        close(daemon_fd);
        if (opts.debug)
            pam_syslog(pamh, LOG_DEBUG,
                       "linuxhello: empty PIN input – deferring to next module");
        return PAM_IGNORE;
    }

    /*
     * ── 6. Send PIN to daemon ──────────────────────────────────────
     *
     * We send the PIN as a length-prefixed string appended to a minimal
     * header.  Wire format reuses lh_auth_request_t with the PIN in the
     * username field (repurposed here); a production implementation would
     * define a dedicated LH_MSG_PIN_RESPONSE message type.
     *
     * NOTE: The PIN is sent over a *local Unix socket* to the daemon
     * running as root on the same machine – this is NOT a network
     * transmission.  The socket is protected by filesystem permissions
     * (/run/linuxhello/ is 0700 root:root).
     */
    lh_auth_request_t pin_msg;
    memset(&pin_msg, 0, sizeof(pin_msg));
    pin_msg.hdr.type   = LH_MSG_SIGNATURE; /* re-using type slot for PIN */
    pin_msg.hdr.length = (uint16_t)sizeof(pin_msg);
    if (pin_token && *pin_token)
        strncpy(pin_msg.username, pin_token, sizeof(pin_msg.username) - 1);

    if (send_all(daemon_fd, &pin_msg, sizeof(pin_msg)) != 0) {
        pam_syslog(pamh, LOG_ERR, "linuxhello: send PIN failed");
        close(daemon_fd);
        if (pin_token) free((void *)pin_token);
        return opts.allow_fallback ? PAM_IGNORE : PAM_AUTH_ERR;
    }
    /*
     * Remember whether the user actually typed a PIN before we zero it.
     * This drives the error-return policy below: if a non-empty PIN was
     * entered and the daemon rejects it, we return PAM_AUTH_ERR so the
     * PAM stack fails immediately.  We must NOT return PAM_IGNORE in that
     * case because PAM_IGNORE causes the next module (pam_unix) to run,
     * which would prompt for a password and give the appearance of a
     * double-prompt even after the user correctly entered their PIN.
     */
    bool pin_was_entered = (pin_token != NULL && *pin_token != '\0');
    /* Securely zero the PIN token once sent (capture length before zero) */
    if (pin_token) {
        size_t pin_len = strlen(pin_token);
        memset((void *)pin_token, 0, pin_len);
        free((void *)pin_token);
    }

    /* ── 7. Receive auth result ───────────────────────────────────── */
    lh_auth_result_msg_t result;
    if (recv_all(daemon_fd, &result, sizeof(result)) != 0) {
        pam_syslog(pamh, LOG_ERR, "linuxhello: receive result failed");
        close(daemon_fd);
        return opts.allow_fallback ? PAM_IGNORE : PAM_AUTH_ERR;
    }
    close(daemon_fd);

    if (opts.debug)
        pam_syslog(pamh, LOG_DEBUG,
                   "linuxhello: auth result=%d attempts_left=%d for user %s",
                   result.result, result.attempts, username);

    switch (result.result) {
    case LH_OK:
        pam_syslog(pamh, LOG_INFO,
                   "linuxhello: authentication succeeded for user %s", username);
        return PAM_SUCCESS;

    case LH_ERR_LOCKED:
        pam_syslog(pamh, LOG_WARNING,
                   "linuxhello: account locked out for user %s", username);
        return PAM_MAXTRIES;

    case LH_ERR_NO_CRED:
        pam_syslog(pamh, LOG_INFO,
                   "linuxhello: no credential for user %s", username);
        return opts.allow_fallback ? PAM_IGNORE : PAM_USER_UNKNOWN;

    case LH_ERR_BAD_SIG:
    case LH_ERR_BIOMETRIC:
        pam_syslog(pamh, LOG_WARNING,
                   "linuxhello: authentication failed for user %s "
                   "(%d attempts remaining)", username, result.attempts);
        /*
         * The user entered a PIN that the TPM rejected.  Return
         * PAM_AUTH_ERR unconditionally so the PAM stack stops here and
         * does NOT fall through to pam_unix.  Falling through would show
         * a second password prompt, which is the exact double-prompt bug
         * we are fixing.  PAM_IGNORE is reserved for the empty-PIN case
         * ("use password instead") handled earlier in the function.
         */
        if (pin_was_entered)
            return PAM_AUTH_ERR;
        return opts.allow_fallback ? PAM_IGNORE : PAM_AUTH_ERR;

    case LH_ERR_TPM:
        pam_syslog(pamh, LOG_WARNING,
                   "linuxhello: TPM unavailable for user %s – "
                   "falling back to next auth module", username);
        /*
         * TPM hardware failure is not the user's fault.  Allow fallback
         * to password auth so the user can still log in even when the
         * TPM is temporarily unavailable (e.g., after a firmware update).
         */
        return opts.allow_fallback ? PAM_IGNORE : PAM_AUTHINFO_UNAVAIL;

    default:
        pam_syslog(pamh, LOG_ERR,
                   "linuxhello: unknown result %d for user %s",
                   result.result, username);
        if (pin_was_entered)
            return PAM_AUTH_ERR;
        return opts.allow_fallback ? PAM_IGNORE : PAM_AUTH_ERR;
    }
}

/* ── pam_sm_setcred ──────────────────────────────────────── */

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh,
                               int           flags,
                               int           argc,
                               const char  **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

/* ── pam_sm_acct_mgmt ────────────────────────────────────── */

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh,
                                  int           flags,
                                  int           argc,
                                  const char  **argv)
{
    (void)flags;
    lh_pam_opts_t opts;
    parse_opts(argc, argv, &opts);

    const char *username = NULL;
    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username)
        return opts.allow_fallback ? PAM_IGNORE : PAM_USER_UNKNOWN;

    /*
     * Check that the user has an enrolled LinuxHello credential.
     * We check the file directly here (read-only, no daemon needed).
     * The actual authentication gate is pam_sm_authenticate.
     */
    char pubkey_path[256];
    snprintf(pubkey_path, sizeof(pubkey_path), LH_PUBKEY_FILE_FMT, username);

    if (access(pubkey_path, F_OK) != 0)
        return opts.allow_fallback ? PAM_IGNORE : PAM_ACCT_EXPIRED;

    return PAM_SUCCESS;
}

/* ── pam_sm_open_session / pam_sm_close_session ──────────── */

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,
                                    int           flags,
                                    int           argc,
                                    const char  **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,
                                     int           flags,
                                     int           argc,
                                     const char  **argv)
{
    (void)pamh; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}

/* ── pam_sm_chauthtok ────────────────────────────────────── */

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh,
                                 int           flags,
                                 int           argc,
                                 const char  **argv)
{
    (void)flags; (void)argc; (void)argv;
    pam_syslog(pamh, LOG_INFO,
               "linuxhello: PIN/credential changes must be done via lh-enroll");
    return PAM_AUTHTOK_ERR;
}
