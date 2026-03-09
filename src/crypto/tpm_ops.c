/*
 * tpm_ops.c – TPM 2.0 ESAPI operations for LinuxHello
 *
 * File organisation:
 *   Part 1: Always-compiled functions (OpenSSL only)
 *     - lh_verify_signature
 *     - derive_key_from_pin, lh_sw_create_key, lh_sw_sign (degraded mode)
 *   Part 2: TPM-dependent functions (#ifndef LH_NO_TPM2)
 *     - lh_tpm_init, lh_tpm_available, lh_tpm_teardown
 *     - lh_tpm_create_key, lh_tpm_load_key, lh_tpm_sign
 *     - lh_tpm_delete_key
 *     - lh_tpm_nv_* (NVRAM lockout counter)
 *   Part 3: Stubs for when TPM is unavailable (#else)
 */

#include "tpm_ops.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/x509.h>

#include "../common/linuxhello.h"

/* ═══════════════════════════════════════════════════════════
 * Part 1: Always-compiled functions (OpenSSL only)
 * ═══════════════════════════════════════════════════════════ */

/* ── lh_verify_signature ─────────────────────────────────── */

int lh_verify_signature(const uint8_t *pubkey_der,  size_t pubkey_der_len,
                         const uint8_t *challenge,   size_t challenge_len,
                         const uint8_t *sig_der,     size_t sig_der_len)
{
    const unsigned char *p = pubkey_der;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)pubkey_der_len);
    if (!pkey) return LH_ERR_BAD_SIG;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { EVP_PKEY_free(pkey); return LH_ERR_GENERIC; }

    int rc = LH_ERR_BAD_SIG;
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
        EVP_DigestVerifyUpdate(mdctx, challenge, challenge_len) == 1     &&
        EVP_DigestVerifyFinal(mdctx, sig_der, sig_der_len) == 1)
    {
        rc = LH_OK;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return rc;
}

/* ── Degraded mode helpers ───────────────────────────────── */

/*
 * Derive an AES-256 key from the PIN using PBKDF2-SHA256.
 * salt is a 16-byte value stored alongside the encrypted key.
 */
static int derive_key_from_pin(const char    *pin,
                                const uint8_t *salt,
                                uint8_t       *out_key /* 32 bytes */)
{
    return PKCS5_PBKDF2_HMAC(pin, (int)strlen(pin),
                              salt, 16,
                              LH_DEGRADED_KEY_ITER,
                              EVP_sha256(),
                              32, out_key) == 1 ? 0 : -1;
}

int lh_sw_create_key(const char  *username,
                     const char  *pin,
                     lh_pubkey_t *out_pub)
{
    if (!pin || strlen(pin) < 4) {
        fprintf(stderr, "[linuxhello] PIN must be at least 4 characters\n");
        return -1;
    }

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) return -1;

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0)
    {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx);

    unsigned char *pub_der_p = out_pub->der;
    int pub_len = i2d_PUBKEY(pkey, &pub_der_p);
    if (pub_len <= 0) { EVP_PKEY_free(pkey); return -1; }
    out_pub->der_len = (size_t)pub_len;

    unsigned char *priv_der = NULL;
    int priv_len = i2d_PrivateKey(pkey, &priv_der);
    EVP_PKEY_free(pkey);
    if (priv_len <= 0) return -1;

    uint8_t salt[16];
    if (RAND_bytes(salt, sizeof(salt)) != 1) {
        OPENSSL_free(priv_der);
        return -1;
    }

    uint8_t aes_key[32];
    if (derive_key_from_pin(pin, salt, aes_key) != 0) {
        OPENSSL_cleanse(aes_key, sizeof(aes_key));
        OPENSSL_free(priv_der);
        return -1;
    }

    uint8_t iv[12];
    if (RAND_bytes(iv, sizeof(iv)) != 1) {
        OPENSSL_cleanse(aes_key, sizeof(aes_key));
        OPENSSL_free(priv_der);
        return -1;
    }

    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    unsigned char *ct = malloc((size_t)priv_len + 16);
    uint8_t tag[16];
    int ct_len = 0, final_len = 0;

    if (!cctx || !ct                                                          ||
        !EVP_EncryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, aes_key, iv)      ||
        !EVP_EncryptUpdate(cctx, ct, &ct_len, priv_der, priv_len)            ||
        !EVP_EncryptFinal_ex(cctx, ct + ct_len, &final_len)                  ||
        !EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_GET_TAG, 16, tag))
    {
        OPENSSL_cleanse(aes_key, sizeof(aes_key));
        OPENSSL_free(priv_der);
        if (cctx) EVP_CIPHER_CTX_free(cctx);
        free(ct);
        return -1;
    }
    EVP_CIPHER_CTX_free(cctx);
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    OPENSSL_cleanse(priv_der, (size_t)priv_len);
    OPENSSL_free(priv_der);
    ct_len += final_len;

    /* Write: salt(16) || iv(12) || tag(16) || ciphertext */
    char path[256];
    snprintf(path, sizeof(path), LH_DEGRADED_KEY_FILE_FMT, username);

    int fd = open(path, O_WRONLY|O_CREAT|O_EXCL, 0600);
    if (fd < 0) { free(ct); return -1; }

    ssize_t w1 = write(fd, salt, 16);
    ssize_t w2 = write(fd, iv,   12);
    ssize_t w3 = write(fd, tag,  16);
    ssize_t w4 = write(fd, ct,   (size_t)ct_len);
    close(fd);
    free(ct);

    if (w1 != 16 || w2 != 12 || w3 != 16 || w4 != (ssize_t)ct_len) {
        unlink(path); /* remove partial file */
        return -1;
    }
    return 0;
}

int lh_sw_sign(const char      *username,
               const char      *pin,
               const uint8_t   *challenge,
               lh_signature_t  *out_sig)
{
    char path[256];
    snprintf(path, sizeof(path), LH_DEGRADED_KEY_FILE_FMT, username);

    /* Open first, then stat the open fd to avoid TOCTOU race */
    int key_fd = open(path, O_RDONLY);
    if (key_fd < 0) return LH_ERR_NO_CRED;

    struct stat st;
    if (fstat(key_fd, &st) < 0 || st.st_size < 44) {
        close(key_fd);
        return LH_ERR_GENERIC;
    }

    FILE *f = fdopen(key_fd, "rb");
    if (!f) { close(key_fd); return LH_ERR_GENERIC; }

    uint8_t salt[16], iv[12], tag[16];
    if (fread(salt, 1, 16, f) != 16 ||
        fread(iv,   1, 12, f) != 12 ||
        fread(tag,  1, 16, f) != 16)
    {
        fclose(f);
        return LH_ERR_GENERIC;
    }

    size_t ct_len = (size_t)(st.st_size - 44);
    unsigned char *ct = malloc(ct_len);
    if (!ct) { fclose(f); return LH_ERR_GENERIC; }
    if (fread(ct, 1, ct_len, f) != ct_len) {
        free(ct); fclose(f); return LH_ERR_GENERIC;
    }
    fclose(f);

    uint8_t aes_key[32];
    if (derive_key_from_pin(pin, salt, aes_key) != 0) {
        free(ct);
        return LH_ERR_GENERIC;
    }

    unsigned char *pt = malloc(ct_len);
    if (!pt) {
        OPENSSL_cleanse(aes_key, sizeof(aes_key));
        free(ct);
        return LH_ERR_GENERIC;
    }

    EVP_CIPHER_CTX *cctx = EVP_CIPHER_CTX_new();
    int pt_len = 0, final_len = 0;
    int rc_dec = LH_ERR_BAD_SIG;

    if (EVP_DecryptInit_ex(cctx, EVP_aes_256_gcm(), NULL, aes_key, iv)  &&
        EVP_DecryptUpdate(cctx, pt, &pt_len, ct, (int)ct_len)           &&
        EVP_CIPHER_CTX_ctrl(cctx, EVP_CTRL_GCM_SET_TAG, 16, tag)        &&
        EVP_DecryptFinal_ex(cctx, pt + pt_len, &final_len) > 0)
    {
        rc_dec = LH_OK;
    }
    EVP_CIPHER_CTX_free(cctx);
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    free(ct);

    if (rc_dec != LH_OK) {
        OPENSSL_cleanse(pt, ct_len);
        free(pt);
        return LH_ERR_BAD_SIG;
    }

    const unsigned char *p = pt;
    EVP_PKEY *pkey = d2i_AutoPrivateKey(NULL, &p, (long)(pt_len + final_len));
    OPENSSL_cleanse(pt, ct_len);
    free(pt);
    if (!pkey) return LH_ERR_GENERIC;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    size_t sig_len = LH_SIG_MAX_LEN;
    int signed_ok = (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
                     EVP_DigestSignUpdate(mdctx, challenge, LH_CHALLENGE_LEN) == 1  &&
                     EVP_DigestSignFinal(mdctx, out_sig->der, &sig_len) == 1);
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);

    if (!signed_ok) return LH_ERR_GENERIC;
    out_sig->der_len = sig_len;
    return LH_OK;
}

/* ═══════════════════════════════════════════════════════════
 * Part 2: TPM-dependent functions
 * ═══════════════════════════════════════════════════════════ */
#ifndef LH_NO_TPM2

static void lh_log_tpm_error(const char *fn, TSS2_RC rc)
{
    fprintf(stderr, "[linuxhello] %s failed: %s (0x%08x)\n",
            fn, Tss2_RC_Decode(rc), (unsigned)rc);
}

/* Convert TPMS_ECC_POINT to DER SubjectPublicKeyInfo via OpenSSL */
static int ecc_point_to_der(const TPMS_ECC_POINT *pt,
                             uint8_t *der_buf, size_t *der_len)
{
    EC_GROUP *grp = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!grp) return -1;

    EC_POINT *ec_pt = EC_POINT_new(grp);
    if (!ec_pt) { EC_GROUP_free(grp); return -1; }

    BIGNUM *x = BN_bin2bn(pt->x.buffer, pt->x.size, NULL);
    BIGNUM *y = BN_bin2bn(pt->y.buffer, pt->y.size, NULL);
    if (!x || !y) goto fail;

    if (!EC_POINT_set_affine_coordinates(grp, ec_pt, x, y, NULL))
        goto fail;

    EC_KEY *eckey = EC_KEY_new();
    if (!eckey) goto fail;
    EC_KEY_set_group(eckey, grp);
    EC_KEY_set_public_key(eckey, ec_pt);

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) { EC_KEY_free(eckey); goto fail; }
    EVP_PKEY_assign_EC_KEY(pkey, eckey);

    unsigned char *dp = der_buf;
    int len = i2d_PUBKEY(pkey, &dp);
    EVP_PKEY_free(pkey);
    if (len <= 0) goto fail;
    *der_len = (size_t)len;

    BN_free(x); BN_free(y);
    EC_POINT_free(ec_pt);
    EC_GROUP_free(grp);
    return 0;

fail:
    BN_free(x); BN_free(y);
    EC_POINT_free(ec_pt);
    EC_GROUP_free(grp);
    return -1;
}

/* ── lh_tpm_init ─────────────────────────────────────────── */

int lh_tpm_init(lh_tpm_ctx_t *ctx)
{
    memset(ctx, 0, sizeof(*ctx));

    /*
     * TCTI selection: prefer the kernel in-kernel resource manager
     * (/dev/tpmrm0) over the default, which is tpm2-abrmd via D-Bus.
     *
     * Rationale: the daemon forks a child process per authentication
     * request.  D-Bus connections are NOT fork-safe – after fork() the
     * child cannot reliably establish a new D-Bus session, causing
     * Esys_Initialize to fail with a "TPM init failed" error even when
     * tpm2-abrmd is running.  The kernel device TCTI bypasses D-Bus
     * entirely and is safe to open in a forked child.
     *
     * Fallback chain:
     *   1. device:/dev/tpmrm0  – kernel RM, fork-safe, no D-Bus
     *   2. NULL (default TCTI) – tpm2-abrmd, suitable for non-forking
     *      callers such as lh-enroll
     */
    TSS2_TCTI_CONTEXT *tcti = NULL;
    TSS2_RC trc = Tss2_TctiLdr_Initialize("device:/dev/tpmrm0", &tcti);
    if (trc != TSS2_RC_SUCCESS) {
        /* /dev/tpmrm0 unavailable – try abrmd via default TCTI */
        tcti = NULL;
    }

    TSS2_RC rc = Esys_Initialize(&ctx->ectx, tcti, NULL);
    if (tcti && rc != TSS2_RC_SUCCESS) {
        /* Device TCTI loaded but Esys refused it – free and retry default */
        Tss2_TctiLdr_Finalize(&tcti);
        tcti = NULL;
        rc = Esys_Initialize(&ctx->ectx, NULL, NULL);
    }
    if (rc != TSS2_RC_SUCCESS) {
        if (tcti) Tss2_TctiLdr_Finalize(&tcti);
        lh_log_tpm_error("Esys_Initialize", rc);
        return -1;
    }
    /* tcti is now owned by ctx->ectx; do not free separately */

    TPMS_TIME_INFO *time_info = NULL;
    rc = Esys_ReadClock(ctx->ectx,
                        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                        &time_info);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_ReadClock", rc);
        Esys_Finalize(&ctx->ectx);
        return -1;
    }
    Esys_Free(time_info);

    ctx->initialised = true;
    return 0;
}

bool lh_tpm_available(lh_tpm_ctx_t *ctx)
{
    return ctx && ctx->initialised;
}

void lh_tpm_teardown(lh_tpm_ctx_t *ctx)
{
    if (!ctx) return;
    if (ctx->ectx) Esys_Finalize(&ctx->ectx);
    ctx->initialised = false;
}

/* ── lh_tpm_create_key ───────────────────────────────────── */

int lh_tpm_create_key(lh_tpm_ctx_t *ctx,
                      const char   *pin,
                      TPM2_HANDLE  *out_handle,
                      lh_pubkey_t  *out_pub)
{
    if (!ctx->initialised) return -1;

    TSS2_RC rc;
    ESYS_TR primary     = ESYS_TR_NONE;
    ESYS_TR key_obj     = ESYS_TR_NONE;
    ESYS_TR persistent  = ESYS_TR_NONE;
    ESYS_TR trial_sess  = ESYS_TR_NONE;

    TPM2B_SENSITIVE_CREATE sensitive_create = { .size = 0 };
    TPM2B_PUBLIC primary_template = {
        .size = 0,
        .publicArea = {
            .type    = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            .objectAttributes = (TPMA_OBJECT_FIXEDTPM         |
                                  TPMA_OBJECT_FIXEDPARENT      |
                                  TPMA_OBJECT_SENSITIVEDATAORIGIN |
                                  TPMA_OBJECT_USERWITHAUTH     |
                                  TPMA_OBJECT_RESTRICTED       |
                                  TPMA_OBJECT_DECRYPT          |
                                  TPMA_OBJECT_NODA),
            .parameters.eccDetail = {
                .symmetric = { .algorithm = TPM2_ALG_AES,
                               .keyBits.aes = 128,
                               .mode.aes = TPM2_ALG_CFB },
                .scheme    = { .scheme = TPM2_ALG_NULL },
                .curveID   = TPM2_ECC_NIST_P256,
                .kdf       = { .scheme = TPM2_ALG_NULL },
            },
            .unique.ecc = { .x = { .size = 0 }, .y = { .size = 0 } },
        }
    };
    TPM2B_DATA         outside_info  = { .size = 0 };
    TPML_PCR_SELECTION creation_pcrs = { .count = 0 };

    rc = Esys_CreatePrimary(ctx->ectx, ESYS_TR_RH_OWNER,
                            ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                            &sensitive_create, &primary_template,
                            &outside_info, &creation_pcrs,
                            &primary, NULL, NULL, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_CreatePrimary", rc);
        return -1;
    }

    /* Build policy digest: PolicyCommandCode(Sign) + PolicyAuthValue */
    rc = Esys_StartAuthSession(ctx->ectx, ESYS_TR_NONE, ESYS_TR_NONE,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               NULL, TPM2_SE_TRIAL,
                               &(TPMT_SYM_DEF){ .algorithm = TPM2_ALG_NULL },
                               TPM2_ALG_SHA256, &trial_sess);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_StartAuthSession(trial)", rc);
        goto cleanup;
    }

    rc = Esys_PolicyCommandCode(ctx->ectx, trial_sess,
                                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                TPM2_CC_Sign);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_PolicyCommandCode", rc); goto cleanup;
    }

    rc = Esys_PolicyAuthValue(ctx->ectx, trial_sess,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_PolicyAuthValue", rc); goto cleanup;
    }

    TPM2B_DIGEST *policy_digest = NULL;
    rc = Esys_PolicyGetDigest(ctx->ectx, trial_sess,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &policy_digest);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_PolicyGetDigest", rc); goto cleanup;
    }
    Esys_FlushContext(ctx->ectx, trial_sess);
    trial_sess = ESYS_TR_NONE;

    /* Create the signing key */
    size_t pin_len = pin ? strlen(pin) : 0;
    TPM2B_SENSITIVE_CREATE key_sensitive = { .size = 0 };
    if (pin && pin_len) {
        size_t auth_sz = (pin_len > sizeof(TPMU_HA)) ? sizeof(TPMU_HA) : pin_len;
        key_sensitive.sensitive.userAuth.size = (uint16_t)auth_sz;
        memcpy(key_sensitive.sensitive.userAuth.buffer, pin, auth_sz);
    }

    TPM2B_PUBLIC key_template = {
        .size = 0,
        .publicArea = {
            .type    = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA256,
            /*
             * Non-negotiable attributes:
             *   fixedTPM    – key cannot be migrated to another TPM
             *   fixedParent – key cannot be re-parented
             *   sensitiveDataOrigin – generated on-chip
             *   sign        – signing-only (no decrypt)
             */
            .objectAttributes = (TPMA_OBJECT_FIXEDTPM            |
                                  TPMA_OBJECT_FIXEDPARENT         |
                                  TPMA_OBJECT_SENSITIVEDATAORIGIN  |
                                  TPMA_OBJECT_USERWITHAUTH         |
                                  TPMA_OBJECT_SIGN_ENCRYPT),
            .authPolicy = *policy_digest,
            .parameters.eccDetail = {
                .symmetric = { .algorithm = TPM2_ALG_NULL },
                .scheme    = { .scheme = TPM2_ALG_ECDSA,
                               .details.ecdsa = { .hashAlg = TPM2_ALG_SHA256 } },
                .curveID = TPM2_ECC_NIST_P256,
                .kdf     = { .scheme = TPM2_ALG_NULL },
            },
            .unique.ecc = { .x = { .size = 0 }, .y = { .size = 0 } },
        }
    };
    Esys_Free(policy_digest);

    TPM2B_PRIVATE *key_priv = NULL;
    TPM2B_PUBLIC  *key_pub  = NULL;
    rc = Esys_Create(ctx->ectx, primary,
                     ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                     &key_sensitive, &key_template,
                     &outside_info, &creation_pcrs,
                     &key_priv, &key_pub, NULL, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_Create", rc); goto cleanup;
    }

    rc = Esys_Load(ctx->ectx, primary,
                   ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                   key_priv, key_pub, &key_obj);
    Esys_Free(key_priv);
    Esys_Free(key_pub);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_Load", rc); goto cleanup;
    }

    *out_handle = LH_TPM_HANDLE_BASE;

    /*
     * If this persistent handle is already occupied (e.g. from a previous
     * enrollment that was disk-purged without revoking the TPM key), evict
     * the stale object now so the new key can be persisted at this slot.
     */
    {
        ESYS_TR stale = ESYS_TR_NONE;
        TSS2_RC probe = Esys_TR_FromTPMPublic(ctx->ectx, *out_handle,
                            ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                            &stale);
        if (probe == TSS2_RC_SUCCESS && stale != ESYS_TR_NONE) {
            fprintf(stderr,
                    "[linuxhello] TPM handle 0x%08x already occupied "
                    "(stale from previous enrollment) – evicting...\n",
                    *out_handle);
            ESYS_TR evicted = ESYS_TR_NONE;   /* must be non-NULL pointer */
            TSS2_RC evict_rc =
                Esys_EvictControl(ctx->ectx,
                                  ESYS_TR_RH_OWNER, stale,
                                  ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                  *out_handle, &evicted);
            if (evict_rc != TSS2_RC_SUCCESS)
                lh_log_tpm_error("Esys_EvictControl (evict stale)", evict_rc);
            /* Continue regardless – the EvictControl below will tell us
               whether the slot is now free. */
        }
    }

    rc = Esys_EvictControl(ctx->ectx,
                           ESYS_TR_RH_OWNER, key_obj,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           *out_handle, &persistent);
    Esys_FlushContext(ctx->ectx, key_obj);
    key_obj = ESYS_TR_NONE;
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_EvictControl", rc); goto cleanup;
    }

    /* Export public key as DER */
    TPM2B_PUBLIC *persisted_pub = NULL;
    rc = Esys_ReadPublic(ctx->ectx, persistent,
                         ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                         &persisted_pub, NULL, NULL);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_ReadPublic", rc); goto cleanup;
    }

    int conv_rc = ecc_point_to_der(&persisted_pub->publicArea.unique.ecc,
                                    out_pub->der, &out_pub->der_len);
    Esys_Free(persisted_pub);
    if (conv_rc != 0) goto cleanup;

    Esys_FlushContext(ctx->ectx, primary);
    return 0;

cleanup:
    if (trial_sess != ESYS_TR_NONE) Esys_FlushContext(ctx->ectx, trial_sess);
    if (key_obj    != ESYS_TR_NONE) Esys_FlushContext(ctx->ectx, key_obj);
    if (primary    != ESYS_TR_NONE) Esys_FlushContext(ctx->ectx, primary);
    return -1;
}

/* ── lh_tpm_load_key ─────────────────────────────────────── */

int lh_tpm_load_key(lh_tpm_ctx_t *ctx,
                    TPM2_HANDLE   persistent_handle,
                    ESYS_TR      *out_key_obj)
{
    TSS2_RC rc = Esys_TR_FromTPMPublic(ctx->ectx, persistent_handle,
                                       ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                       out_key_obj);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_TR_FromTPMPublic", rc);
        return -1;
    }
    return 0;
}

/* ── lh_tpm_sign ─────────────────────────────────────────── */

int lh_tpm_sign(lh_tpm_ctx_t   *ctx,
                ESYS_TR         key_obj,
                const char     *pin,
                const uint8_t  *challenge,
                lh_signature_t *out_sig)
{
    if (!ctx->initialised) return LH_ERR_TPM;

    TSS2_RC rc;
    ESYS_TR policy_session = ESYS_TR_NONE;

    rc = Esys_StartAuthSession(ctx->ectx, ESYS_TR_NONE, ESYS_TR_NONE,
                               ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                               NULL, TPM2_SE_POLICY,
                               &(TPMT_SYM_DEF){ .algorithm = TPM2_ALG_NULL },
                               TPM2_ALG_SHA256, &policy_session);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_StartAuthSession(policy)", rc);
        return LH_ERR_TPM;
    }

    rc = Esys_PolicyCommandCode(ctx->ectx, policy_session,
                                ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                TPM2_CC_Sign);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_PolicyCommandCode", rc);
        Esys_FlushContext(ctx->ectx, policy_session);
        return LH_ERR_TPM;
    }

    rc = Esys_PolicyAuthValue(ctx->ectx, policy_session,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_PolicyAuthValue", rc);
        Esys_FlushContext(ctx->ectx, policy_session);
        return LH_ERR_TPM;
    }

    size_t pin_len = pin ? strlen(pin) : 0;
    TPM2B_AUTH auth_val = { .size = 0 };
    if (pin && pin_len) {
        auth_val.size = (uint16_t)(pin_len > sizeof(TPMU_HA) ?
                                   sizeof(TPMU_HA) : pin_len);
        memcpy(auth_val.buffer, pin, auth_val.size);
    }
    Esys_TR_SetAuth(ctx->ectx, key_obj, &auth_val);

    TPM2B_DIGEST digest = { .size = SHA256_DIGEST_LENGTH };
    SHA256(challenge, LH_CHALLENGE_LEN, digest.buffer);

    TPMT_SIG_SCHEME scheme = {
        .scheme        = TPM2_ALG_ECDSA,
        .details.ecdsa = { .hashAlg = TPM2_ALG_SHA256 },
    };
    TPMT_TK_HASHCHECK validation = {
        .tag       = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_NULL,
        .digest    = { .size = 0 },
    };

    TPMT_SIGNATURE *tpm_sig = NULL;
    rc = Esys_Sign(ctx->ectx, key_obj,
                   policy_session, ESYS_TR_NONE, ESYS_TR_NONE,
                   &digest, &scheme, &validation, &tpm_sig);
    Esys_FlushContext(ctx->ectx, policy_session);

    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_Sign", rc);
        return LH_ERR_TPM;
    }

    ECDSA_SIG *ecdsa = ECDSA_SIG_new();
    BIGNUM *r = BN_bin2bn(tpm_sig->signature.ecdsa.signatureR.buffer,
                          tpm_sig->signature.ecdsa.signatureR.size, NULL);
    BIGNUM *s = BN_bin2bn(tpm_sig->signature.ecdsa.signatureS.buffer,
                          tpm_sig->signature.ecdsa.signatureS.size, NULL);
    ECDSA_SIG_set0(ecdsa, r, s);
    Esys_Free(tpm_sig);

    unsigned char *der_p = out_sig->der;
    int der_len = i2d_ECDSA_SIG(ecdsa, &der_p);
    ECDSA_SIG_free(ecdsa);
    if (der_len <= 0) return LH_ERR_GENERIC;
    out_sig->der_len = (size_t)der_len;
    return LH_OK;
}

/* ── lh_tpm_delete_key ───────────────────────────────────── */

int lh_tpm_delete_key(lh_tpm_ctx_t *ctx, TPM2_HANDLE persistent_handle)
{
    ESYS_TR key_obj;
    TSS2_RC rc = Esys_TR_FromTPMPublic(ctx->ectx, persistent_handle,
                                       ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                       &key_obj);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_TR_FromTPMPublic (delete)", rc);
        return -1;
    }

    ESYS_TR evicted = ESYS_TR_NONE;
    rc = Esys_EvictControl(ctx->ectx,
                           ESYS_TR_RH_OWNER, key_obj,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                           persistent_handle, &evicted);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_EvictControl (evict)", rc);
        return -1;
    }
    return 0;
}

/* ── lh_tpm_evict_range ──────────────────────────────────── */

int lh_tpm_evict_range(lh_tpm_ctx_t *ctx,
                        TPM2_HANDLE   base,
                        TPM2_HANDLE   max,
                        uint32_t     *out_evicted)
{
    if (out_evicted) *out_evicted = 0;

    /*
     * Paginate through TPM2_CAP_HANDLES starting at `base`.  The TPM
     * returns handles in ascending order; we stop once all returned
     * handles exceed `max` or the page is empty.
     */
    TPMI_YES_NO      more = TPM2_YES;
    TPM2_HANDLE      next = base;

    while (more == TPM2_YES) {
        TPMS_CAPABILITY_DATA *cap = NULL;
        TSS2_RC rc = Esys_GetCapability(ctx->ectx,
                                         ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                         TPM2_CAP_HANDLES,
                                         next,
                                         128,
                                         &more,
                                         &cap);
        if (rc != TSS2_RC_SUCCESS) {
            lh_log_tpm_error("Esys_GetCapability (evict_range)", rc);
            return -1;
        }

        TPML_HANDLE *hl = &cap->data.handles;
        if (hl->count == 0) { Esys_Free(cap); break; }

        bool any_in_range = false;
        for (uint32_t i = 0; i < hl->count; i++) {
            TPM2_HANDLE h = hl->handle[i];
            if (h < base) continue;
            if (h > max)  { more = TPM2_NO; break; } /* past our range */
            any_in_range = true;
            if (lh_tpm_delete_key(ctx, h) == 0) {
                if (out_evicted) (*out_evicted)++;
            }
        }

        /* Advance past the last handle we saw to avoid re-fetching it */
        next = hl->handle[hl->count - 1] + 1;
        Esys_Free(cap);

        if (!any_in_range || next > max) break;
    }
    return 0;
}

/* ── NVRAM lockout counter ───────────────────────────────── */

int lh_tpm_nv_init_counter(lh_tpm_ctx_t *ctx, uint32_t user_slot)
{
    TPM2_HANDLE nv_handle = LH_TPM_NV_BASE + (user_slot & 0xFFFFU);
    TPM2B_AUTH nv_auth = { .size = 0 };

    TPMS_NV_PUBLIC nv_pub = {
        .nvIndex    = nv_handle,
        .nameAlg    = TPM2_ALG_SHA256,
        .attributes = (TPMA_NV_OWNERWRITE | TPMA_NV_OWNERREAD | (TPMA_NV)(TPM2_NT_COUNTER << 4)),
        .authPolicy = { .size = 0 },
        .dataSize   = sizeof(uint64_t),
    };
    TPM2B_NV_PUBLIC nv_public = {
        .size     = sizeof(TPMS_NV_PUBLIC),
        .nvPublic = nv_pub,
    };

    TSS2_RC rc = Esys_NV_DefineSpace(ctx->ectx, ESYS_TR_RH_OWNER,
                                     ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                                     &nv_auth, &nv_public, NULL);
    if (rc == TPM2_RC_NV_DEFINED) return 0;
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_NV_DefineSpace", rc);
        return -1;
    }
    return 0;
}

int lh_tpm_nv_read_counter(lh_tpm_ctx_t *ctx,
                            uint32_t      user_slot,
                            uint32_t     *count)
{
    TPM2_HANDLE nv_handle = LH_TPM_NV_BASE + (user_slot & 0xFFFFU);
    ESYS_TR nv_obj;
    TSS2_RC rc = Esys_TR_FromTPMPublic(ctx->ectx, nv_handle,
                                       ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                       &nv_obj);
    if (rc != TSS2_RC_SUCCESS) { *count = 0; return 0; }

    TPM2B_MAX_NV_BUFFER *data = NULL;
    rc = Esys_NV_Read(ctx->ectx, ESYS_TR_RH_OWNER, nv_obj,
                      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                      sizeof(uint64_t), 0, &data);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_NV_Read", rc);
        return -1;
    }
    uint64_t val;
    memcpy(&val, data->buffer, sizeof(uint64_t));
    Esys_Free(data);
    *count = (uint32_t)(val & 0xFFFFFFFFU);
    return 0;
}

int lh_tpm_nv_increment_counter(lh_tpm_ctx_t *ctx, uint32_t user_slot)
{
    TPM2_HANDLE nv_handle = LH_TPM_NV_BASE + (user_slot & 0xFFFFU);
    ESYS_TR nv_obj;
    TSS2_RC rc = Esys_TR_FromTPMPublic(ctx->ectx, nv_handle,
                                       ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                       &nv_obj);
    if (rc != TSS2_RC_SUCCESS) return -1;

    rc = Esys_NV_Increment(ctx->ectx, ESYS_TR_RH_OWNER, nv_obj,
                           ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_NV_Increment", rc);
        return -1;
    }
    return 0;
}

int lh_tpm_nv_reset_counter(lh_tpm_ctx_t *ctx, uint32_t user_slot)
{
    TPM2_HANDLE nv_handle = LH_TPM_NV_BASE + (user_slot & 0xFFFFU);
    ESYS_TR nv_obj;
    TSS2_RC rc = Esys_TR_FromTPMPublic(ctx->ectx, nv_handle,
                                       ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                                       &nv_obj);
    if (rc != TSS2_RC_SUCCESS) return 0;

    rc = Esys_NV_UndefineSpace(ctx->ectx, ESYS_TR_RH_OWNER, nv_obj,
                               ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE);
    if (rc != TSS2_RC_SUCCESS) {
        lh_log_tpm_error("Esys_NV_UndefineSpace", rc);
        return -1;
    }
    return lh_tpm_nv_init_counter(ctx, user_slot);
}

/* ═══════════════════════════════════════════════════════════
 * Part 3: Stubs when TPM is unavailable
 * ═══════════════════════════════════════════════════════════ */
#else /* LH_NO_TPM2 */

int lh_tpm_init(lh_tpm_ctx_t *ctx)
{
    if (ctx) memset(ctx, 0, sizeof(*ctx));
    return -1;
}

bool lh_tpm_available(lh_tpm_ctx_t *ctx)
{
    return ctx && ctx->initialised;
}

void lh_tpm_teardown(lh_tpm_ctx_t *ctx)
{
    if (ctx) memset(ctx, 0, sizeof(*ctx));
}

int lh_tpm_create_key(lh_tpm_ctx_t *ctx,
                      const char   *pin,
                      TPM2_HANDLE  *out_handle,
                      lh_pubkey_t  *out_pub)
{
    (void)ctx; (void)pin; (void)out_handle; (void)out_pub;
    return -1;
}

int lh_tpm_load_key(lh_tpm_ctx_t *ctx,
                    TPM2_HANDLE   h,
                    ESYS_TR      *obj)
{
    (void)ctx; (void)h; (void)obj;
    return -1;
}

int lh_tpm_sign(lh_tpm_ctx_t   *ctx,
                ESYS_TR         key_obj,
                const char     *pin,
                const uint8_t  *challenge,
                lh_signature_t *out_sig)
{
    (void)ctx; (void)key_obj; (void)pin; (void)challenge; (void)out_sig;
    return LH_ERR_TPM;
}

int lh_tpm_delete_key(lh_tpm_ctx_t *ctx, TPM2_HANDLE h)
{
    (void)ctx; (void)h;
    return -1;
}

int lh_tpm_nv_init_counter(lh_tpm_ctx_t *ctx, uint32_t s)
{
    (void)ctx; (void)s;
    return -1;
}

int lh_tpm_nv_read_counter(lh_tpm_ctx_t *ctx, uint32_t s, uint32_t *c)
{
    (void)ctx; (void)s;
    if (c) *c = 0;
    return -1;
}

int lh_tpm_nv_increment_counter(lh_tpm_ctx_t *ctx, uint32_t s)
{
    (void)ctx; (void)s;
    return -1;
}

int lh_tpm_nv_reset_counter(lh_tpm_ctx_t *ctx, uint32_t s)
{
    (void)ctx; (void)s;
    return -1;
}

#endif /* LH_NO_TPM2 */
