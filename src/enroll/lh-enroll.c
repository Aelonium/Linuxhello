/*
 * lh-enroll.c – LinuxHello Enrollment CLI Tool
 *
 * Usage:
 *   lh-enroll enroll   [--user <username>] [--no-biometric] [--degraded]
 *   lh-enroll revoke   [--user <username>]
 *   lh-enroll status   [--user <username>]
 *   lh-enroll rotate   [--user <username>]
 *
 * Must be run as root (or via sudo) because it writes to /var/lib/linuxhello/
 * and interacts with the TPM.
 *
 * Enrollment flow:
 *   1.  Verify the invoking user has permission to enroll @username
 *   2.  Check for an existing credential (warn/abort on duplicate)
 *   3.  Initialise TPM context (detect degraded mode if unavailable)
 *   4.  Generate the key pair (TPM or software)
 *   5.  Prompt for PIN (required; minimum 4 characters)
 *   6.  Store the public key and metadata
 *   7.  Initialise NVRAM lockout counter (TPM mode)
 *   8.  Optionally enrol biometric via fprintd
 *   9.  Print confirmation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <termios.h>
#include <time.h>
#include <signal.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>

#include <openssl/sha.h>

#include "../common/linuxhello.h"
#include "../crypto/tpm_ops.h"
#include "../storage/storage.h"
#include "../biometric/ir_face.h"

/* ── Helpers ─────────────────────────────────────────────── */

/** Read a PIN from the terminal without echo */
static int read_pin_noecho(const char *prompt, char *buf, size_t buf_len)
{
    struct termios old, tmp;
    printf("%s", prompt);
    fflush(stdout);

    if (tcgetattr(STDIN_FILENO, &old) != 0) {
        /* Not a tty (e.g., piped) – just read normally */
        if (!fgets(buf, (int)buf_len, stdin)) return -1;
        buf[strcspn(buf, "\n")] = '\0';
        return 0;
    }

    tmp = old;
    tmp.c_lflag &= ~(tcflag_t)(ECHO | ECHOE | ECHOK | ECHONL);
    tcsetattr(STDIN_FILENO, TCSANOW, &tmp);

    int rc = (fgets(buf, (int)buf_len, stdin) != NULL) ? 0 : -1;
    tcsetattr(STDIN_FILENO, TCSANOW, &old);
    printf("\n");

    if (rc == 0)
        buf[strcspn(buf, "\n")] = '\0';
    return rc;
}

/** Confirm that a username maps to a valid local account */
static int validate_username(const char *username)
{
    struct passwd *pw = getpwnam(username);
    if (!pw) {
        fprintf(stderr, "Error: user '%s' does not exist\n", username);
        return -1;
    }
    return 0;
}

/* ── Command: enroll ─────────────────────────────────────── */

static int cmd_enroll(const char *username,
                       bool        no_biometric,
                       bool        force_degraded)
{
    if (geteuid() != 0) {
        fprintf(stderr, "Error: enrollment must be run as root\n");
        return 1;
    }

    if (validate_username(username) != 0) return 1;

    /* Warn if credential already exists */
    if (lh_storage_credential_exists(username)) {
        fprintf(stderr,
                "Warning: a credential already exists for user '%s'.\n"
                "Use 'lh-enroll revoke --user %s' first, or "
                "'lh-enroll rotate' to replace.\n",
                username, username);
        return 1;
    }

    /* Ensure storage directory exists */
    if (lh_storage_init() != 0) {
        fprintf(stderr, "Error: cannot initialise storage: %s\n",
                strerror(errno));
        return 1;
    }

    /* Detect TPM availability */
    lh_tpm_ctx_t tpm;
    bool tpm_ok = !force_degraded && (lh_tpm_init(&tpm) == 0);
    if (!tpm_ok && !force_degraded) {
        fprintf(stderr,
                "Warning: TPM 2.0 unavailable – falling back to degraded "
                "(software key) mode.\n"
                "  *** This provides SIGNIFICANTLY weaker security. ***\n"
                "  The private key will be encrypted on disk; a root attacker\n"
                "  may be able to extract it with sufficient effort.\n\n");
    }

    /* Prompt for PIN */
    char pin[128]     = { 0 };
    char pin_conf[128]= { 0 };

    printf("LinuxHello Enrollment for user: %s\n", username);
    printf("Choose a PIN (minimum 4 characters, no maximum):\n");

#define LH_PIN_MAX_ATTEMPTS 5
    int pin_attempts = 0;
    do {
        if (pin_attempts >= LH_PIN_MAX_ATTEMPTS) {
            fprintf(stderr,
                    "Error: too many failed PIN attempts (%d). Aborting.\n",
                    LH_PIN_MAX_ATTEMPTS);
            return 1;
        }
        pin_attempts++;

        if (read_pin_noecho("  Enter PIN: ", pin, sizeof(pin)) != 0) {
            fprintf(stderr, "Error reading PIN\n");
            return 1;
        }
        if (strlen(pin) < 4) {
            fprintf(stderr, "PIN must be at least 4 characters. Try again.\n");
            memset(pin, 0, sizeof(pin));
            continue;
        }
        if (read_pin_noecho("  Confirm PIN: ", pin_conf, sizeof(pin_conf)) != 0) {
            fprintf(stderr, "Error reading PIN confirmation\n");
            memset(pin, 0, sizeof(pin));
            return 1;
        }
        if (strcmp(pin, pin_conf) != 0) {
            fprintf(stderr, "PINs do not match. Try again. (%d/%d)\n",
                    pin_attempts, LH_PIN_MAX_ATTEMPTS);
            memset(pin,      0, sizeof(pin));
            memset(pin_conf, 0, sizeof(pin_conf));
        } else {
            break;
        }
    } while (1);
    memset(pin_conf, 0, sizeof(pin_conf));

    /* Generate key */
    lh_credential_t cred;
    memset(&cred, 0, sizeof(cred));
    strncpy(cred.username,  username,    sizeof(cred.username)  - 1);
    strncpy(cred.key_type,  "ECC_P256",  sizeof(cred.key_type)  - 1);
    cred.enrolled_at    = time(NULL);
    cred.degraded_mode  = !tpm_ok;
    cred.tpm_available  = tpm_ok;
    cred.user_slot      = (uint32_t)(cred.enrolled_at & 0xFFFF);

    printf("Generating key pair... ");
    fflush(stdout);

    int key_rc;
    if (tpm_ok) {
        lh_pubkey_t pub_out;
        key_rc = lh_tpm_create_key(&tpm, pin, &cred.tpm_handle, &pub_out);
        if (key_rc == 0) {
            memcpy(cred.pubkey_der, pub_out.der, pub_out.der_len);
            cred.pubkey_der_len = pub_out.der_len;
        }
    } else {
        lh_pubkey_t pub_out;
        key_rc = lh_sw_create_key(username, pin, &pub_out);
        if (key_rc == 0) {
            memcpy(cred.pubkey_der, pub_out.der, pub_out.der_len);
            cred.pubkey_der_len = pub_out.der_len;
            cred.tpm_handle = 0;
        }
    }

    /* Zero the PIN as soon as the key is generated */
    memset(pin, 0, sizeof(pin));

    if (key_rc != 0) {
        fprintf(stderr, "FAILED\nError: key generation failed\n");
        if (tpm_ok) lh_tpm_teardown(&tpm);
        return 1;
    }
    printf("OK\n");

    /* Compute SHA-256 of the public key for integrity */
    SHA256(cred.pubkey_der, cred.pubkey_der_len, cred.pubkey_sha256);

    /* Initialise TPM NVRAM lockout counter */
    if (tpm_ok) {
        if (lh_tpm_nv_init_counter(&tpm, cred.user_slot) != 0) {
            fprintf(stderr,
                    "Warning: could not create TPM NVRAM lockout counter "
                    "(software counter will be used as fallback)\n");
        }
        lh_tpm_teardown(&tpm);
    }

    /* Biometric enrollment – IR face recognition */
    strncpy(cred.biometric_type, "none", sizeof(cred.biometric_type) - 1);
    cred.biometric_enrolled = false;

    if (!no_biometric) {
        printf("\nIR face enrollment:\n");
        printf("  IR camera: auto-detect (default %s, GREY format, 640x360)\n",
               LH_IR_DEVICE);
        if (lh_face_is_enrolled(username))
            printf("  Note: a face template is already present and will be "
                   "replaced.\n");
        printf("  Skip biometric enrollment? [Y/n] ");
        fflush(stdout);
        char ans[8] = { 0 };
        if (fgets(ans, sizeof(ans), stdin) &&
            (ans[0] == 'n' || ans[0] == 'N'))
        {
            /*
             * User chose to enroll biometric.  Test the IR camera FIRST.
             * If the camera is not functional we must abort the enrollment
             * entirely rather than silently falling back to PIN-only mode,
             * because the user explicitly requested biometric enrollment.
             * A silent fallback would leave the system configured without
             * the biometric the user expected.
             */
            printf("  Testing IR camera (auto-detect)... ");
            fflush(stdout);

            int cam_rc = lh_ir_camera_test();
            if (cam_rc != LH_FACE_OK) {
                printf("FAILED (rc=%d)\n", cam_rc);
                fprintf(stderr,
                        "\nError: IR camera is not working (rc=%d).\n"
                        "  Biometric enrollment cannot proceed.\n\n"
                        "  The partially-created credential will be removed.\n"
                        "  Fix the IR camera first, then re-run enrollment.\n\n"
                        "  Quick diagnostics:\n"
                        "    ls -la /dev/video*\n"
                        "    v4l2-ctl --list-devices\n"
                        "    sudo dmesg | grep -iE 'uvc|video|camera'\n\n",
                        cam_rc);

                /* Clean up the credential we already wrote to disk */
                lh_storage_delete_credential(username);
                return 1;
            }
            printf("OK\n");

            int face_rc = lh_face_enroll(username,
                                          cred.pubkey_der,
                                          cred.pubkey_der_len);
            if (face_rc == LH_FACE_OK) {
                strncpy(cred.biometric_type, "face_ir",
                        sizeof(cred.biometric_type) - 1);
                cred.biometric_enrolled = true;
                printf("  IR face enrolled successfully.\n");
            } else {
                fprintf(stderr,
                        "\nError: IR face enrollment failed (rc=%d).\n"
                        "  The partially-created credential will be removed.\n"
                        "  If the camera opened but faces were not detected,\n"
                        "  ensure good IR illumination and position your face\n"
                        "  within 30–60 cm of the camera.\n",
                        face_rc);
                lh_storage_delete_credential(username);
                return 1;
            }
        } else {
            printf("  Skipping biometric enrollment; PIN-only mode.\n");
        }
    }

    /* Save credential */
    if (lh_storage_save_credential(&cred) != 0) {
        fprintf(stderr, "Error: failed to save credential: %s\n",
                strerror(errno));
        return 1;
    }

    printf("\n=== LinuxHello enrollment complete ===\n");
    printf("  User:      %s\n", cred.username);
    printf("  Key type:  %s\n", cred.key_type);
    printf("  TPM mode:  %s\n", tpm_ok ? "YES (hardware-protected)" :
                                          "NO  (degraded software mode)");
    printf("  Biometric: %s\n", cred.biometric_enrolled ?
                                  cred.biometric_type : "none");
    if (tpm_ok)
        printf("  TPM handle: 0x%08x\n", cred.tpm_handle);

    printf("\nAdd to PAM stack (e.g., /etc/pam.d/common-auth):\n");
    printf("  auth  [success=done new_authtok_reqd=ok ignore=ignore auth_err=die default=ignore]  pam_linuxhello.so\n");
    return 0;
}

/* ── Command: revoke ─────────────────────────────────────── */

static int cmd_revoke(const char *username)
{
    if (geteuid() != 0) {
        fprintf(stderr, "Error: revocation must be run as root\n");
        return 1;
    }

    if (!lh_storage_credential_exists(username)) {
        fprintf(stderr, "No LinuxHello credential found for user '%s'\n",
                username);
        return 1;
    }

    /* Load credential to get TPM handle */
    lh_credential_t cred;
    if (lh_storage_load_credential(username, &cred) == LH_OK &&
        cred.tpm_available && cred.tpm_handle != 0)
    {
        lh_tpm_ctx_t tpm;

        /*
         * lh_tpm_init() connects to tpm2-abrmd over D-Bus / Unix socket and
         * can block indefinitely if the daemon is absent or busy.  Install
         * SIGALRM as SIG_IGN so the alarm interrupts blocking syscalls
         * (returning EINTR) without killing the process, then cancel after.
         */
        struct sigaction sa_old;
        struct sigaction sa_alrm;
        memset(&sa_alrm, 0, sizeof(sa_alrm));
        sa_alrm.sa_handler = SIG_IGN;
        sigaction(SIGALRM, &sa_alrm, &sa_old);
        alarm(10);
        int tpm_rc = lh_tpm_init(&tpm);
        alarm(0);
        sigaction(SIGALRM, &sa_old, NULL);

        if (tpm_rc == 0) {
            printf("Removing TPM key (handle 0x%08x)... ", cred.tpm_handle);
            fflush(stdout);
            if (lh_tpm_delete_key(&tpm, cred.tpm_handle) == 0)
                printf("OK\n");
            else
                printf("WARNING: TPM key removal failed (may already be gone)\n");
            lh_tpm_nv_reset_counter(&tpm, cred.user_slot);
            lh_tpm_teardown(&tpm);
        } else {
            printf("WARNING: TPM unreachable – skipping hardware key removal.\n"
                   "         The TPM handle 0x%08x may be a dangling entry.\n"
                   "         Use 'tpm2_evictcontrol' manually if needed.\n",
                   cred.tpm_handle);
        }
    }

    /* Remove biometric (face) template */
    if (cred.biometric_enrolled) {
        printf("Removing face template... ");
        fflush(stdout);
        if (lh_face_delete(username) == 0)
            printf("OK\n");
        else
            printf("WARNING: face template removal failed\n");
    }

    /* Remove credential files */
    if (lh_storage_delete_credential(username) != 0) {
        fprintf(stderr, "Error: failed to remove credential files\n");
        return 1;
    }

    printf("LinuxHello credential revoked for user '%s'\n", username);
    return 0;
}

/* ── Command: purge ─────────────────────────────────────────
 *
 * Directly removes all on-disk credential files for a user (or every user
 * with --all) without touching the TPM or fprintd.  Use this when:
 *   • lh-enroll revoke blocks because tpm2-abrmd is unavailable
 *   • a credential was enrolled for the wrong user
 *   • you need a clean slate before re-enrolling
 *
 * TPM handles and biometric templates are left behind; clean those up
 * manually via 'tpm2_evictcontrol' and 'fprintd-delete' if needed.
 * ─────────────────────────────────────────────────────────── */

static int cmd_purge(const char *username)
{
    if (geteuid() != 0) {
        fprintf(stderr, "Error: purge must be run as root\n");
        return 1;
    }
    if (!lh_storage_credential_exists(username)) {
        printf("No credential files found for user '%s' – nothing to do.\n",
               username);
        return 0;
    }
    printf("Purging credential files for user '%s'... ", username);
    fflush(stdout);
    if (lh_storage_delete_credential(username) != 0) {
        fprintf(stderr, "FAILED: %s\n", strerror(errno));
        return 1;
    }
    /* Also remove face embedding if present */
    lh_face_delete(username);
    printf("OK\n");
    return 0;
}

static int cmd_purge_all(void)
{
    if (geteuid() != 0) {
        fprintf(stderr, "Error: purge must be run as root\n");
        return 1;
    }

    DIR *d = opendir(LH_STATE_DIR);
    if (!d) {
        if (errno == ENOENT) {
            printf("No credential store found at %s – nothing to do.\n",
                   LH_STATE_DIR);
            return 0;
        }
        fprintf(stderr, "Error: cannot open %s: %s\n",
                LH_STATE_DIR, strerror(errno));
        return 1;
    }

    int purged = 0;
    int errors = 0;
    struct dirent *ent;

    while ((ent = readdir(d)) != NULL) {
        /* Skip . and .. and any plain files at the top level */
        if (ent->d_name[0] == '.')
            continue;

        /* Confirm it's a directory before treating it as a user entry */
        char full[512];
        snprintf(full, sizeof(full), LH_STATE_DIR "/%s", ent->d_name);
        struct stat st;
        if (stat(full, &st) != 0 || !S_ISDIR(st.st_mode))
            continue;

        printf("  purging '%s'... ", ent->d_name);
        fflush(stdout);
        if (lh_storage_delete_credential(ent->d_name) == 0) {
            printf("OK\n");
            purged++;
        } else {
            printf("FAILED (%s)\n", strerror(errno));
            errors++;
        }
    }
    closedir(d);

    if (purged == 0 && errors == 0)
        printf("No credential entries found – nothing to do.\n");
    else
        printf("Purge complete: %d purged, %d error(s).\n", purged, errors);

    return errors > 0 ? 1 : 0;
}

/* ── Command: purge-tpm ──────────────────────────────────────
 *
 * Evicts all LinuxHello persistent handles from the TPM without touching
 * credential files.  Use when enrollment left stale TPM handles behind
 * (error 0x14c: "persistent object already defined").
 *
 * After running this, re-enroll with: sudo lh-enroll enroll --user <name>
 * ─────────────────────────────────────────────────────────── */

static int cmd_purge_tpm(void)
{
    if (geteuid() != 0) {
        fprintf(stderr, "Error: purge-tpm must be run as root\n");
        return 1;
    }

    printf("Scanning TPM for stale LinuxHello handles "
           "(0x%08x–0x%08x)...\n",
           LH_TPM_HANDLE_BASE, LH_TPM_HANDLE_MAX);
    fflush(stdout);

    lh_tpm_ctx_t tpm;

    /* Same SIGALRM guard used by cmd_revoke */
    struct sigaction sa_old, sa_alrm;
    memset(&sa_alrm, 0, sizeof(sa_alrm));
    sa_alrm.sa_handler = SIG_IGN;
    sigaction(SIGALRM, &sa_alrm, &sa_old);
    alarm(10);
    int tpm_rc = lh_tpm_init(&tpm);
    alarm(0);
    sigaction(SIGALRM, &sa_old, NULL);

    if (tpm_rc != 0) {
        fprintf(stderr,
                "Error: cannot connect to TPM (is tpm2-abrmd running?)\n"
                "Try: sudo systemctl start tpm2-abrmd\n"
                "Then re-run: sudo lh-enroll purge-tpm\n");
        return 1;
    }

    uint32_t evicted = 0;
    int rc = lh_tpm_evict_range(&tpm,
                                 LH_TPM_HANDLE_BASE, LH_TPM_HANDLE_MAX,
                                 &evicted);
    lh_tpm_teardown(&tpm);

    if (rc != 0) {
        fprintf(stderr, "Error: TPM eviction failed\n");
        return 1;
    }

    if (evicted == 0)
        printf("No stale LinuxHello handles found – TPM is clean.\n");
    else
        printf("Evicted %u stale handle(s) from TPM.\n", evicted);

    return 0;
}

/* ── Command: status ─────────────────────────────────────── */

static int cmd_status(const char *username)
{
    if (!lh_storage_credential_exists(username)) {
        printf("No LinuxHello credential enrolled for user '%s'\n", username);
        return 0;
    }

    lh_credential_t cred;
    if (lh_storage_load_credential(username, &cred) != LH_OK) {
        fprintf(stderr, "Error: failed to load credential\n");
        return 1;
    }

    lh_lockout_t lock;
    lh_storage_load_lockout(username, &lock);

    char ts[64] = "unknown";
    struct tm *tm_info = gmtime(&cred.enrolled_at);
    if (tm_info)
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", tm_info);

    printf("LinuxHello credential status for user: %s\n", username);
    printf("  Key type:            %s\n", cred.key_type);
    printf("  TPM protected:       %s\n", cred.tpm_available ? "yes" : "no");
    printf("  Degraded mode:       %s\n", cred.degraded_mode ? "yes" : "no");
    if (cred.tpm_available)
        printf("  TPM handle:          0x%08x\n", cred.tpm_handle);
    printf("  Biometric:           %s (%s)\n",
           cred.biometric_type,
           cred.biometric_enrolled ? "enrolled" : "not enrolled");
    printf("  Enrolled at:         %s\n", ts);
    printf("  Failed attempts:     %u\n", lock.failed_attempts);
    printf("  Locked out:          %s\n",
           lh_storage_check_lockout(&lock) ? "YES" : "no");
    return 0;
}

/* ── Command: rotate ─────────────────────────────────────── */

static int cmd_rotate(const char *username,
                       bool        no_biometric,
                       bool        force_degraded)
{
    printf("Rotating credential for user '%s':\n", username);
    printf("  Step 1: Revoking existing credential...\n");
    /* Save biometric enrollment state before revoke */
    lh_credential_t old_cred;
    bool had_bio = false;
    if (lh_storage_load_credential(username, &old_cred) == LH_OK)
        had_bio = old_cred.biometric_enrolled;

    if (lh_storage_credential_exists(username))
        cmd_revoke(username);

    printf("  Step 2: Enrolling new credential...\n");
    /* If old cred had biometric and no_biometric not set, keep it */
    if (had_bio && !no_biometric)
        no_biometric = false;

    return cmd_enroll(username, no_biometric, force_degraded);
}

/* ── main ────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s <command> [options]\n\n"
            "Commands:\n"
            "  enroll   [--user <username>] [--no-biometric] [--degraded]\n"
            "  revoke   [--user <username>]\n"
            "  status   [--user <username>]\n"
            "  rotate   [--user <username>] [--no-biometric] [--degraded]\n"
            "  purge    [--user <username> | --all]\n"
            "             Remove on-disk credential files without touching the\n"
            "             TPM or biometrics. Use when 'revoke' blocks or a key\n"
            "             was enrolled for the wrong user.\n"
            "  purge-tpm\n"
            "             Evict stale LinuxHello handles from the TPM (no file\n"
            "             changes). Fix for error 0x14c on re-enroll.\n\n"
            "Options:\n"
            "  --user <username>   Target user (default: current user)\n"
            "  --all               (purge only) purge every enrolled user\n"
            "  --no-biometric      Skip biometric enrollment\n"
            "  --degraded          Force software-key mode (no TPM)\n\n"
            "Version: %d.%d.%d\n",
            prog,
            LH_VERSION_MAJOR, LH_VERSION_MINOR, LH_VERSION_PATCH);
}

int main(int argc, char *argv[])
{
    if (argc < 2) { usage(argv[0]); return 1; }

    const char *cmd          = argv[1];
    char       *username_buf = NULL;   /* heap copy – always use this */
    const char *username     = NULL;
    bool        no_biometric  = false;
    bool        force_degraded = false;
    bool        purge_all      = false;

    /*
     * Resolve the default username when running under sudo / su.
     *
     * Priority:
     *   1. SUDO_USER env var  (set by sudo, absent under "sudo -i" / "su -")
     *   2. /proc/self/loginuid  (kernel-maintained, survives env resets and
     *      "sudo -i").  A value of 4294967295 (0xFFFFFFFF) means unset.
     *   3. getpwuid(getuid()) – last resort; if this resolves to root and
     *      no explicit --user was given we reject the call to avoid
     *      accidentally targeting root.
     *
     * getpwnam()/getpwuid() return pointers into a static buffer that is
     * overwritten by the next pw* call (e.g. inside validate_username()).
     * We strdup() immediately so the pointer stays valid.
     */

    /* 1. SUDO_USER */
    const char *sudo_user = getenv("SUDO_USER");
    if (sudo_user && *sudo_user) {
        errno = 0;
        struct passwd *pw = getpwnam(sudo_user);
        if (pw) username_buf = strdup(pw->pw_name);
    }

    /* 2. /proc/self/loginuid */
    if (!username_buf) {
        FILE *lf = fopen("/proc/self/loginuid", "r");
        if (lf) {
            unsigned long luid = ULONG_MAX;
            if (fscanf(lf, "%lu", &luid) == 1 &&
                luid != ULONG_MAX && luid != 4294967295UL)
            {
                struct passwd *pw = getpwuid((uid_t)luid);
                if (pw) username_buf = strdup(pw->pw_name);
            }
            fclose(lf);
        }
    }

    /* 3. Effective UID fallback */
    if (!username_buf) {
        struct passwd *pw = getpwuid(getuid());
        if (pw) username_buf = strdup(pw->pw_name);
    }

    username = username_buf;

    for (int i = 2; i < argc; i++) {
        if ((strcmp(argv[i], "--user") == 0 || strcmp(argv[i], "-u") == 0)
            && i+1 < argc)
            username = argv[++i];
        else if (strcmp(argv[i], "--no-biometric") == 0)
            no_biometric = true;
        else if (strcmp(argv[i], "--degraded") == 0)
            force_degraded = true;
        else if (strcmp(argv[i], "--all") == 0)
            purge_all = true;
    }

    if (!username || !*username) {
        fprintf(stderr, "Error: cannot determine username\n");
        free(username_buf);
        return 1;
    }

    /* purge --all doesn't need a username at all – dispatch early */
    if (strcmp(cmd, "purge") == 0 && purge_all) {
        free(username_buf);
        return cmd_purge_all();
    }

    if (!username || !*username) {
        fprintf(stderr, "Error: cannot determine username\n");
        free(username_buf);
        return 1;
    }

    /*
     * Safety guard: if the name was auto-detected (not from --user) and it
     * resolved to root, refuse.  Accidentally operating on root's credential
     * is almost always a mistake.  Pass --user root explicitly if intentional.
     */
    if (username == username_buf && strcmp(username, "root") == 0) {
        fprintf(stderr,
                "Error: could not identify the invoking user – resolved to root.\n"
                "Run with --user <username> to specify the target user explicitly.\n");
        free(username_buf);
        return 1;
    }

    if (strcmp(cmd, "enroll") == 0)
        return cmd_enroll(username, no_biometric, force_degraded);
    else if (strcmp(cmd, "revoke") == 0)
        return cmd_revoke(username);
    else if (strcmp(cmd, "status") == 0)
        return cmd_status(username);
    else if (strcmp(cmd, "rotate") == 0)
        return cmd_rotate(username, no_biometric, force_degraded);
    else if (strcmp(cmd, "purge") == 0)
        return cmd_purge(username);
    else if (strcmp(cmd, "purge-tpm") == 0)
        return cmd_purge_tpm();
    else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage(argv[0]);
        return 1;
    }
}
