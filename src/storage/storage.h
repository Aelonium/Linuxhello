/*
 * storage.h – Secure credential storage for LinuxHello
 *
 * Layout under /var/lib/linuxhello/:
 *
 *   /var/lib/linuxhello/                    (root:root 0700)
 *   └── <username>/                         (root:root 0700)
 *       ├── pubkey.der      public key, DER SubjectPublicKeyInfo
 *       ├── meta.json       credential metadata (JSON)
 *       ├── lockout         software lockout state (binary, root:root 0600)
 *       └── privkey.enc     (degraded mode only) encrypted private key
 *
 * All files are owned root:root with restrictive permissions.  The
 * public key is readable by root only; it is handed to the PAM module
 * by the privileged daemon.
 */

#ifndef STORAGE_H
#define STORAGE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <time.h>
#include "../common/linuxhello.h"

/* ── Credential metadata ─────────────────────────────────── */

typedef struct lh_credential {
    char     username[64];
    char     key_type[16];        /* "ECC_P256"                        */
    bool     tpm_available;
    uint32_t tpm_handle;          /* TPM persistent handle (0 if none) */
    bool     degraded_mode;
    uint8_t  pubkey_der[LH_PUBKEY_MAX_LEN];
    size_t   pubkey_der_len;
    uint8_t  pubkey_sha256[32];   /* SHA-256 of pubkey_der             */
    char     biometric_type[32];  /* "fingerprint", "none", etc.       */
    bool     biometric_enrolled;
    time_t   enrolled_at;
    uint32_t user_slot;           /* index used for TPM NV handle      */
} lh_credential_t;

/* ── Lockout state ───────────────────────────────────────── */

typedef struct lh_lockout {
    uint32_t failed_attempts;
    time_t   last_failure;
    bool     locked;
} lh_lockout_t;

/* ── API ─────────────────────────────────────────────────── */

/**
 * lh_storage_init – Create /var/lib/linuxhello with correct permissions.
 * Must be called as root (e.g., from daemon startup).
 * Returns 0 on success.
 */
int lh_storage_init(void);

/**
 * lh_storage_save_credential – Persist a credential for @username.
 *
 * Creates the per-user directory and writes pubkey.der and meta.json.
 * Must be called as root.  Returns 0 on success.
 */
int lh_storage_save_credential(const lh_credential_t *cred);

/**
 * lh_storage_load_credential – Load a credential for @username.
 *
 * Reads and validates pubkey.der and meta.json.
 * Returns 0 on success, LH_ERR_NO_CRED if no credential exists.
 */
int lh_storage_load_credential(const char *username, lh_credential_t *out);

/**
 * lh_storage_delete_credential – Remove all credential files for @username.
 * Returns 0 on success.
 */
int lh_storage_delete_credential(const char *username);

/**
 * lh_storage_credential_exists – Returns true iff a credential exists for
 * @username.
 */
bool lh_storage_credential_exists(const char *username);

/* ── Lockout state ───────────────────────────────────────── */

/**
 * lh_storage_load_lockout – Load the lockout state for @username.
 * If no lockout file exists, returns a zeroed lh_lockout_t (no lockout).
 */
int lh_storage_load_lockout(const char *username, lh_lockout_t *out);

/**
 * lh_storage_save_lockout – Persist lockout state.  Returns 0 on success.
 */
int lh_storage_save_lockout(const char *username, const lh_lockout_t *lock);

/**
 * lh_storage_check_lockout – Returns true if the account is currently
 * locked out (LH_MAX_ATTEMPTS failures within LH_LOCKOUT_SECONDS).
 * Also updates the in-memory lockout struct.
 */
bool lh_storage_check_lockout(lh_lockout_t *lock);

/**
 * lh_storage_record_failure – Increment failed attempts counter, set
 * locked=true if threshold reached.  Saves to disk.
 */
int lh_storage_record_failure(const char *username);

/**
 * lh_storage_reset_lockout – Reset the failure counter on successful auth.
 */
int lh_storage_reset_lockout(const char *username);

#endif /* STORAGE_H */
