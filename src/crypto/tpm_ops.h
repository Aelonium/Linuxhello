/*
 * tpm_ops.h – TPM 2.0 ESAPI key-management operations
 *
 * Provides non-exportable ECC P-256 key creation, persistent storage,
 * signing, and NVRAM-backed lockout counters using the tpm2-tss ESAPI.
 *
 * All private key material is generated inside the TPM and never
 * exported – TPM2_CC_CreateLoaded with fixedTPM|fixedParent attributes
 * enforces the hardware boundary.
 */

#ifndef TPM_OPS_H
#define TPM_OPS_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* tpm2-tss ESAPI headers (package: libtss2-dev) */
#ifndef LH_NO_TPM2
#  include <tss2/tss2_esys.h>
#  include <tss2/tss2_tpm2_types.h>
#  include <tss2/tss2_rc.h>
#else
/* Minimal type stubs so this header compiles without tpm2-tss installed */
typedef uint32_t TPM2_HANDLE;
typedef uint32_t ESYS_TR;
typedef int      TSS2_RC;
#  define ESYS_TR_NONE 0U
/* Forward-declare the opaque ESAPI context so pointers compile */
typedef struct ESYS_CONTEXT ESYS_CONTEXT;
#endif

#include "../common/linuxhello.h"

/* ── Handle ranges ───────────────────────────────────────── */
/**
 * Persistent handle space: 0x81000000 – 0x817FFFFF (owner hierarchy).
 * We allocate one handle per local user:
 *   0x81000001 = first enrolled user
 *   0x81000002 = second enrolled user
 *   …
 * The exact mapping is stored in the per-user meta.json.
 */
#define LH_TPM_HANDLE_BASE   0x81000001U
#define LH_TPM_HANDLE_MAX    0x8100FFFFU

/**
 * NVRAM index for the per-user software lockout counter.
 * Layout: 0x01500000 + (user_slot & 0xFFFF)
 * Each index stores a single uint32 (4 bytes): failed-attempt count.
 */
#define LH_TPM_NV_BASE       0x01500000U

/* ── Context ─────────────────────────────────────────────── */
typedef struct lh_tpm_ctx {
    ESYS_CONTEXT *ectx;          /* ESAPI context                      */
    bool          initialised;
} lh_tpm_ctx_t;

/* ── Key material ────────────────────────────────────────── */
typedef struct lh_pubkey {
    uint8_t der[LH_PUBKEY_MAX_LEN]; /* DER-encoded SubjectPublicKeyInfo */
    size_t  der_len;
} lh_pubkey_t;

typedef struct lh_signature {
    uint8_t der[LH_SIG_MAX_LEN];
    size_t  der_len;
} lh_signature_t;

/* ── API ─────────────────────────────────────────────────── */

/**
 * lh_tpm_init – Connect to the TPM via the resource manager (tpm2-abrmd
 *   or /dev/tpm0 tabd).  Returns 0 on success; sets ctx->initialised.
 *
 * On systems without a TPM lh_tpm_available() will return false and the
 * caller should fall back to degraded (software) mode.
 */
int lh_tpm_init(lh_tpm_ctx_t *ctx);

/** lh_tpm_available – Returns true if a TPM was successfully initialised */
bool lh_tpm_available(lh_tpm_ctx_t *ctx);

/** lh_tpm_teardown – Free resources, flush transient objects */
void lh_tpm_teardown(lh_tpm_ctx_t *ctx);

/**
 * lh_tpm_create_key – Create a non-exportable ECC P-256 signing key.
 *
 * The key is created with the following mandatory attributes:
 *   fixedTPM      – prevents migration to another TPM
 *   fixedParent   – prevents re-parenting
 *   sensitiveDataOrigin – key generated on-chip
 *   userWithAuth  – use requires an authorisation session
 *   sign          – this is a signing-only key (no decrypt)
 *
 * Policy binding:
 *   An authPolicy session ties the key to TPM2_PolicyAuthValue (PIN)
 *   and/or TPM2_PolicyCommandCode(TPM2_CC_Sign) so the key can only
 *   be used for signing after local PIN/biometric authorisation.
 *
 * @param ctx         Initialised TPM context
 * @param pin         PIN string (used as authValue for the key; may be NULL
 *                    in which case the key is PIN-free – NOT recommended)
 * @param out_handle  Receives the persistent handle (TPM2_HANDLE)
 * @param out_pub     Receives the public key in DER form
 *
 * Returns 0 on success.
 */
int lh_tpm_create_key(lh_tpm_ctx_t   *ctx,
                      const char     *pin,
                      TPM2_HANDLE    *out_handle,
                      lh_pubkey_t    *out_pub);

/**
 * lh_tpm_load_key – Load a previously persisted key into a transient
 * ESAPI object ready for use.  Returns 0 on success.
 */
int lh_tpm_load_key(lh_tpm_ctx_t *ctx,
                    TPM2_HANDLE   persistent_handle,
                    ESYS_TR      *out_key_obj);

/**
 * lh_tpm_sign – Sign a challenge using the key identified by key_obj.
 *
 * The caller must have already unlocked the policy session (PIN or
 * biometric gate).  The TPM will use ECDSA with SHA-256.
 *
 * @param ctx         Initialised TPM context
 * @param key_obj     Loaded key object (from lh_tpm_load_key)
 * @param pin         PIN for policy session authorisation
 * @param challenge   Raw bytes to sign (LH_CHALLENGE_LEN bytes)
 * @param out_sig     Receives the DER-encoded ECDSA signature
 *
 * Returns 0 on success; LH_ERR_TPM on TPM error (including DA lockout).
 */
int lh_tpm_sign(lh_tpm_ctx_t     *ctx,
                ESYS_TR           key_obj,
                const char       *pin,
                const uint8_t    *challenge,
                lh_signature_t   *out_sig);

/**
 * lh_tpm_verify_signature – Verify an ECDSA-P256 signature using the
 * stored public key.
 *
 * This is done in software via OpenSSL so it does not require TPM access
 * at verification time (PAM path).  Returns 0 if the signature is valid.
 */
int lh_tpm_verify_signature(const lh_pubkey_t   *pubkey,
                             const uint8_t       *challenge,
                             const lh_signature_t *sig);

/**
 * lh_tpm_delete_key – Evict the persistent key from TPM storage and
 * remove the NVRAM lockout index.  Used during credential revocation.
 */
int lh_tpm_delete_key(lh_tpm_ctx_t *ctx, TPM2_HANDLE persistent_handle);

/* ── NVRAM lockout counter ───────────────────────────────── */

/**
 * lh_tpm_nv_init_counter – Allocate an NVRAM counter index for a user.
 * If the index already exists this is a no-op.  Returns 0 on success.
 */
int lh_tpm_nv_init_counter(lh_tpm_ctx_t *ctx, uint32_t user_slot);

/**
 * lh_tpm_nv_read_counter – Read the current failed-attempt count.
 * Returns 0 on success; sets *count.
 */
int lh_tpm_nv_read_counter(lh_tpm_ctx_t *ctx,
                            uint32_t      user_slot,
                            uint32_t     *count);

/**
 * lh_tpm_nv_increment_counter – Atomically increment the counter.
 * Returns 0 on success.
 */
int lh_tpm_nv_increment_counter(lh_tpm_ctx_t *ctx, uint32_t user_slot);

/**
 * lh_tpm_nv_reset_counter – Reset the counter to zero on successful auth.
 * Returns 0 on success.
 */
int lh_tpm_nv_reset_counter(lh_tpm_ctx_t *ctx, uint32_t user_slot);

/* ── Degraded mode (software key, no TPM) ────────────────── */

/**
 * lh_sw_create_key – Generate an ECC P-256 key pair in software.
 *
 * The private key is encrypted with AES-256-GCM using a key derived from
 * the PIN via PBKDF2-SHA256 (LH_DEGRADED_KEY_ITER iterations) and stored
 * in LH_DEGRADED_KEY_FILE_FMT.
 *
 * WARNING: This does NOT provide the same security guarantees as the TPM
 * path.  See linuxhello.h for the degraded-mode risk tradeoffs.
 */
int lh_sw_create_key(const char  *username,
                     const char  *pin,
                     lh_pubkey_t *out_pub);

/**
 * lh_sw_sign – Sign a challenge using the software-protected key.
 *
 * Decrypts the private key using the supplied PIN, performs ECDSA-P256
 * signing, then securely erases the in-memory key material.
 */
int lh_sw_sign(const char       *username,
               const char       *pin,
               const uint8_t    *challenge,
               lh_signature_t   *out_sig);

/**
 * lh_verify_signature – Verify a P-256 ECDSA signature against a
 * DER-encoded SubjectPublicKeyInfo public key.  Works for both TPM and
 * degraded-mode credentials.
 */
int lh_verify_signature(const uint8_t *pubkey_der, size_t pubkey_der_len,
                         const uint8_t *challenge,  size_t challenge_len,
                         const uint8_t *sig_der,    size_t sig_der_len);

#endif /* TPM_OPS_H */
