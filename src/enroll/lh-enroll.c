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
#include <unistd.h>
#include <errno.h>
#include <termios.h>
#include <time.h>
#include <sys/types.h>
#include <pwd.h>

#include <openssl/sha.h>

#include "../common/linuxhello.h"
#include "../crypto/tpm_ops.h"
#include "../storage/storage.h"
#include "../biometric/fprintd_client.h"

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

    do {
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
            fprintf(stderr, "PINs do not match. Try again.\n");
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

    /* Biometric enrollment */
    strncpy(cred.biometric_type, "none", sizeof(cred.biometric_type) - 1);
    cred.biometric_enrolled = false;

    if (!no_biometric) {
        printf("\nFingerprint enrollment (optional):\n");
        printf("  A fingerprint reader was %sdetected.\n",
               lh_bio_is_enrolled(username) ? "already used and " : "");
        printf("  Skip? [Y/n] ");
        char ans[8] = { 0 };
        if (fgets(ans, sizeof(ans), stdin) &&
            (ans[0] == 'n' || ans[0] == 'N'))
        {
            printf("  Starting fingerprint enrollment via fprintd...\n");
            if (lh_bio_enroll(username) == 0) {
                strncpy(cred.biometric_type, "fingerprint",
                        sizeof(cred.biometric_type) - 1);
                cred.biometric_enrolled = true;
                printf("  Fingerprint enrolled successfully.\n");
            } else {
                printf("  Fingerprint enrollment failed; "
                       "PIN-only mode will be used.\n");
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
    printf("  auth  sufficient  pam_linuxhello.so\n");
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
        if (lh_tpm_init(&tpm) == 0) {
            printf("Removing TPM key (handle 0x%08x)... ", cred.tpm_handle);
            fflush(stdout);
            if (lh_tpm_delete_key(&tpm, cred.tpm_handle) == 0)
                printf("OK\n");
            else
                printf("WARNING: TPM key removal failed (may already be gone)\n");
            lh_tpm_nv_reset_counter(&tpm, cred.user_slot);
            lh_tpm_teardown(&tpm);
        }
    }

    /* Remove biometric enrollment */
    if (cred.biometric_enrolled) {
        printf("Removing fprintd enrollment... ");
        fflush(stdout);
        if (lh_bio_delete_enrolled(username) == 0)
            printf("OK\n");
        else
            printf("WARNING: fprintd removal failed\n");
    }

    /* Remove credential files */
    if (lh_storage_delete_credential(username) != 0) {
        fprintf(stderr, "Error: failed to remove credential files\n");
        return 1;
    }

    printf("LinuxHello credential revoked for user '%s'\n", username);
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
            "  rotate   [--user <username>] [--no-biometric] [--degraded]\n\n"
            "Options:\n"
            "  --user <username>   Target user (default: current user)\n"
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
    const char *username     = NULL;
    bool        no_biometric = false;
    bool        force_degraded = false;

    /* Get current user as default */
    struct passwd *pw = getpwuid(getuid());
    if (pw) username = pw->pw_name;

    for (int i = 2; i < argc; i++) {
        if ((strcmp(argv[i], "--user") == 0 || strcmp(argv[i], "-u") == 0)
            && i+1 < argc)
            username = argv[++i];
        else if (strcmp(argv[i], "--no-biometric") == 0)
            no_biometric = true;
        else if (strcmp(argv[i], "--degraded") == 0)
            force_degraded = true;
    }

    if (!username || !*username) {
        fprintf(stderr, "Error: cannot determine username\n");
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
    else {
        fprintf(stderr, "Unknown command: %s\n", cmd);
        usage(argv[0]);
        return 1;
    }
}
