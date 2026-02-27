/*
 * lhd.c – LinuxHello Auth Daemon
 *
 * Runs as root.  Listens on /run/linuxhello/auth.sock for connections
 * from the PAM module and handles authentication requests.
 *
 * Each connection is handled in a forked child process to isolate
 * per-user state and prevent a single compromised session from
 * affecting others.
 *
 * Build:
 *   See CMakeLists.txt
 */

#include "lhd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <syslog.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "../crypto/tpm_ops.h"
#include "../crypto/challenge.h"
#include "../biometric/fprintd_client.h"
#include "../storage/storage.h"

/* ── Internal helpers ────────────────────────────────────── */

static int send_all_lhd(int fd, const void *buf, size_t len)
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

static int recv_all_lhd(int fd, void *buf, size_t len)
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

static void send_auth_result(int fd, lh_result_t result, uint8_t attempts)
{
    lh_auth_result_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.hdr.type   = LH_MSG_AUTH_RESULT;
    msg.hdr.length = (uint16_t)sizeof(msg);
    msg.result     = (uint8_t)result;
    msg.attempts   = attempts;
    send_all_lhd(fd, &msg, sizeof(msg));
}

/* ── lhd_handle_auth_request ─────────────────────────────── */

void lhd_handle_auth_request(int client_fd, bool debug)
{
    /* ── 1. Read auth request ─────────────────────────────────────── */
    lh_auth_request_t req;
    if (recv_all_lhd(client_fd, &req, sizeof(req)) != 0) {
        syslog(LOG_ERR, "linuxhello daemon: read auth request failed: %s",
               strerror(errno));
        return;
    }

    if (req.hdr.type != LH_MSG_AUTH_REQUEST) {
        syslog(LOG_ERR, "linuxhello daemon: unexpected message type 0x%02x",
               req.hdr.type);
        return;
    }

    /* NUL-terminate defensively */
    req.username[sizeof(req.username) - 1] = '\0';
    const char *username = req.username;

    if (debug)
        syslog(LOG_DEBUG, "linuxhello daemon: auth request for user '%s'",
               username);

    /* ── 2. Check software lockout ───────────────────────────────── */
    lh_lockout_t lockout;
    lh_storage_load_lockout(username, &lockout);

    if (lh_storage_check_lockout(&lockout)) {
        syslog(LOG_WARNING,
               "linuxhello daemon: user '%s' is locked out (%d failures)",
               username, lockout.failed_attempts);
        send_auth_result(client_fd, LH_ERR_LOCKED, 0);
        return;
    }

    /* ── 3. Load credential ──────────────────────────────────────── */
    lh_credential_t cred;
    int load_rc = lh_storage_load_credential(username, &cred);
    if (load_rc != LH_OK) {
        syslog(LOG_INFO, "linuxhello daemon: no credential for user '%s'",
               username);
        send_auth_result(client_fd, LH_ERR_NO_CRED, 0);
        return;
    }

    /* ── 4. Generate challenge and send to PAM ───────────────────── */
    lh_challenge_msg_t chal_msg;
    memset(&chal_msg, 0, sizeof(chal_msg));
    chal_msg.hdr.type   = LH_MSG_CHALLENGE;
    chal_msg.hdr.length = (uint16_t)sizeof(chal_msg);

    if (lh_challenge_generate(username, chal_msg.challenge) != 0) {
        syslog(LOG_ERR, "linuxhello daemon: challenge generation failed");
        send_auth_result(client_fd, LH_ERR_GENERIC, 0);
        return;
    }

    if (send_all_lhd(client_fd, &chal_msg, sizeof(chal_msg)) != 0) {
        syslog(LOG_ERR, "linuxhello daemon: send challenge failed");
        return;
    }

    /* ── 5. Biometric gate (parallel with PIN prompt on client side) */
    /*
     * If the user has an enrolled fingerprint, we ask fprintd to verify
     * now.  If biometric succeeds we proceed without requiring the PIN.
     * If biometric fails/times out we fall through to PIN verification.
     *
     * IMPORTANT: The biometric result is used only as an "unlock gesture"
     * to decide whether to proceed.  The actual secret is the TPM key;
     * biometric success merely authorises the TPM operation.
     */
    bool bio_ok = false;
    if (cred.biometric_enrolled &&
        strcmp(cred.biometric_type, "fingerprint") == 0)
    {
        lh_bio_result_t bio = lh_bio_verify(username);
        bio_ok = (bio == LH_BIO_OK);
        if (debug)
            syslog(LOG_DEBUG, "linuxhello daemon: biometric result %d for '%s'",
                   (int)bio, username);
    }

    /* ── 6. Receive PIN from PAM client ─────────────────────────── */
    lh_auth_request_t pin_msg;
    if (recv_all_lhd(client_fd, &pin_msg, sizeof(pin_msg)) != 0) {
        syslog(LOG_ERR, "linuxhello daemon: read PIN msg failed");
        return;
    }
    pin_msg.username[sizeof(pin_msg.username) - 1] = '\0';
    const char *pin = pin_msg.username; /* re-used field for PIN */

    /*
     * Gate logic:
     *   - biometric verified  → proceed (PIN not required but accepted)
     *   - biometric not avail → PIN required
     *   - biometric failed    → PIN required (fallback)
     */
    bool gesture_ok = bio_ok;
    if (!gesture_ok && *pin == '\0') {
        syslog(LOG_WARNING,
               "linuxhello daemon: no gesture (bio failed, no PIN) for '%s'",
               username);
        lh_storage_record_failure(username);
        lh_storage_load_lockout(username, &lockout);
        uint8_t remaining = (LH_MAX_ATTEMPTS > lockout.failed_attempts)
                            ? (uint8_t)(LH_MAX_ATTEMPTS - lockout.failed_attempts)
                            : 0;
        send_auth_result(client_fd, LH_ERR_BIOMETRIC, remaining);
        return;
    }

    /* ── 7. TPM signing ──────────────────────────────────────────── */
    lh_signature_t sig;
    memset(&sig, 0, sizeof(sig));
    int sign_rc;

    if (cred.tpm_available && !cred.degraded_mode) {
        lh_tpm_ctx_t tpm;
        if (lh_tpm_init(&tpm) != 0) {
            syslog(LOG_ERR,
                   "linuxhello daemon: TPM init failed for user '%s'", username);
            send_auth_result(client_fd, LH_ERR_TPM, 0);
            return;
        }

        ESYS_TR key_obj;
        if (lh_tpm_load_key(&tpm, cred.tpm_handle, &key_obj) != 0) {
            syslog(LOG_ERR,
                   "linuxhello daemon: load TPM key failed for user '%s'",
                   username);
            lh_tpm_teardown(&tpm);
            send_auth_result(client_fd, LH_ERR_TPM, 0);
            return;
        }

        /*
         * If biometric succeeded, the PIN may be empty.
         * The TPM key was created with PolicyAuthValue; passing an empty
         * PIN here only works if the key was enrolled without a PIN.
         * In the standard flow (PIN enrolled), biometric success still
         * requires the daemon to use the internally cached PIN, or the
         * user provides it.
         *
         * For this skeleton the PIN from the PAM message is used.
         * A production system would store a PIN-derived authValue in a
         * protected credential and retrieve it after biometric success.
         */
        sign_rc = lh_tpm_sign(&tpm, key_obj,
                               (*pin ? pin : NULL),
                               chal_msg.challenge, &sig);

        /* Zero PIN from stack before teardown (capture length first) */
        size_t pin_tpm_len = strlen(pin);
        memset((void *)pin, 0, pin_tpm_len);

        /* Increment TPM NV lockout counter on failure */
        if (sign_rc != LH_OK)
            lh_tpm_nv_increment_counter(&tpm, cred.user_slot);
        else
            lh_tpm_nv_reset_counter(&tpm, cred.user_slot);

        lh_tpm_teardown(&tpm);
    } else {
        /* Degraded (software) mode */
        syslog(LOG_WARNING,
               "linuxhello daemon: using degraded mode for user '%s'", username);
        size_t pin_sw_len = strlen(pin);
        sign_rc = lh_sw_sign(username, pin, chal_msg.challenge, &sig);
        memset((void *)pin, 0, pin_sw_len);
    }

    if (sign_rc != LH_OK) {
        syslog(LOG_WARNING,
               "linuxhello daemon: signing failed (rc=%d) for user '%s'",
               sign_rc, username);
        lh_storage_record_failure(username);
        lh_storage_load_lockout(username, &lockout);
        uint8_t remaining = (LH_MAX_ATTEMPTS > lockout.failed_attempts)
                            ? (uint8_t)(LH_MAX_ATTEMPTS - lockout.failed_attempts)
                            : 0;
        send_auth_result(client_fd, LH_ERR_BAD_SIG, remaining);
        return;
    }

    /* ── 8. Validate the challenge is still fresh ────────────────── */
    if (!lh_challenge_validate(chal_msg.challenge, username)) {
        syslog(LOG_WARNING,
               "linuxhello daemon: stale challenge for user '%s'", username);
        send_auth_result(client_fd, LH_ERR_REPLAY, 0);
        return;
    }

    /* ── 9. Verify signature against stored public key ───────────── */
    int verify_rc = lh_verify_signature(
        cred.pubkey_der,  cred.pubkey_der_len,
        chal_msg.challenge, LH_CHALLENGE_LEN,
        sig.der, sig.der_len);

    if (verify_rc != LH_OK) {
        syslog(LOG_WARNING,
               "linuxhello daemon: signature verification failed for '%s'",
               username);
        lh_storage_record_failure(username);
        lh_storage_load_lockout(username, &lockout);
        uint8_t remaining = (LH_MAX_ATTEMPTS > lockout.failed_attempts)
                            ? (uint8_t)(LH_MAX_ATTEMPTS - lockout.failed_attempts)
                            : 0;
        send_auth_result(client_fd, LH_ERR_BAD_SIG, remaining);
        return;
    }

    /* ── 10. Success ─────────────────────────────────────────────── */
    lh_storage_reset_lockout(username);
    syslog(LOG_INFO,
           "linuxhello daemon: authentication SUCCEEDED for user '%s'", username);
    send_auth_result(client_fd, LH_OK, LH_MAX_ATTEMPTS);
}

/* ── Signal handling ─────────────────────────────────────── */

static volatile sig_atomic_t g_running = 1;

static void sig_handler(int sig)
{
    if (sig == SIGTERM || sig == SIGINT)
        g_running = 0;
    else if (sig == SIGCHLD)
        while (waitpid(-1, NULL, WNOHANG) > 0);  /* reap zombie children */
}

/* ── lhd_run ─────────────────────────────────────────────── */

int lhd_run(const lhd_config_t *config)
{
    openlog("linuxhello-daemon", LOG_PID|LOG_CONS, LOG_AUTH);

    /* Ensure state directory exists */
    if (lh_storage_init() != 0) {
        syslog(LOG_ERR, "linuxhello daemon: cannot init storage: %s",
               strerror(errno));
        return -1;
    }

    /* Create /run/linuxhello/ if needed */
    mkdir("/run/linuxhello", 0700);

    const char *sock_path = config->socket_path
                            ? config->socket_path
                            : LH_DAEMON_SOCKET;

    /* Remove stale socket */
    unlink(sock_path);

    /* Set up listening socket */
    int server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_fd < 0) {
        syslog(LOG_ERR, "linuxhello daemon: socket(): %s", strerror(errno));
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

    if (bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        syslog(LOG_ERR, "linuxhello daemon: bind(%s): %s",
               sock_path, strerror(errno));
        close(server_fd);
        return -1;
    }

    /* Only root can connect */
    chmod(sock_path, 0600);

    if (listen(server_fd, 8) < 0) {
        syslog(LOG_ERR, "linuxhello daemon: listen(): %s", strerror(errno));
        close(server_fd);
        return -1;
    }

    /* Signal handling */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGCHLD, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    /* Daemonise unless running in foreground */
    if (!config->foreground) {
        pid_t pid = fork();
        if (pid < 0) {
            syslog(LOG_ERR, "linuxhello daemon: fork(): %s", strerror(errno));
            close(server_fd);
            return -1;
        }
        if (pid > 0) {
            /* Parent exits */
            close(server_fd);
            return 0;
        }
        setsid();
        /* Redirect stdio to /dev/null */
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            dup2(devnull, STDOUT_FILENO);
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
    }

    /* Write PID file */
    {
        FILE *pf = fopen(LH_DAEMON_PID, "w");
        if (pf) {
            fprintf(pf, "%d\n", (int)getpid());
            fclose(pf);
        }
    }

    syslog(LOG_INFO, "linuxhello daemon started (pid=%d)", (int)getpid());

    while (g_running) {
        int client_fd = accept(server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            syslog(LOG_ERR, "linuxhello daemon: accept(): %s", strerror(errno));
            break;
        }

        pid_t child = fork();
        if (child == 0) {
            /* Child: handle one auth request then exit */
            close(server_fd);
            lhd_handle_auth_request(client_fd, config->debug);
            close(client_fd);
            exit(0);
        }
        close(client_fd);
    }

    syslog(LOG_INFO, "linuxhello daemon stopping");
    close(server_fd);
    unlink(sock_path);
    unlink(LH_DAEMON_PID);
    closelog();
    return 0;
}

/* ── main ────────────────────────────────────────────────── */

int main(int argc, char *argv[])
{
    lhd_config_t config = {
        .socket_path = LH_DAEMON_SOCKET,
        .foreground  = false,
        .debug       = false,
    };

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--foreground") == 0 ||
            strcmp(argv[i], "-f") == 0)
            config.foreground = true;
        else if (strcmp(argv[i], "--debug") == 0 ||
                 strcmp(argv[i], "-d") == 0)
            config.debug = true;
        else if (strcmp(argv[i], "--socket") == 0 && i+1 < argc)
            config.socket_path = argv[++i];
    }

    return lhd_run(&config);
}
