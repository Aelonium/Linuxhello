/*
 * challenge.c – Challenge generation and validation
 */

#include "challenge.h"

#include <string.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>

#include <openssl/rand.h>
#include <openssl/sha.h>

/* ── Internal: compute SHA-256(username || '\0' || hostname) ─────── */
static void compute_user_ctx(const char *username,
                              uint8_t out[SHA256_DIGEST_LENGTH])
{
    char hostname[256] = { 0 };
    gethostname(hostname, sizeof(hostname) - 1);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(out, 0, SHA256_DIGEST_LENGTH); return; }

    unsigned int digest_len = SHA256_DIGEST_LENGTH;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, username, strlen(username) + 1) == 1 &&
        EVP_DigestUpdate(ctx, hostname, strlen(hostname)) == 1     &&
        EVP_DigestFinal_ex(ctx, out, &digest_len) == 1)
    {
        /* success */
    } else {
        memset(out, 0, SHA256_DIGEST_LENGTH);
    }
    EVP_MD_CTX_free(ctx);
}

/* ── lh_challenge_generate ───────────────────────────────── */

int lh_challenge_generate(const char *username, uint8_t out[LH_CHALLENGE_LEN])
{
    /* bytes [0..31]: CSPRNG nonce */
    if (RAND_bytes(out, LH_NONCE_LEN) != 1) return -1;

    /* bytes [32..39]: current Unix timestamp, little-endian */
    uint64_t ts = (uint64_t)time(NULL);
    memcpy(out + LH_NONCE_LEN, &ts, sizeof(uint64_t));

    /* bytes [40..71]: SHA-256(username || '\0' || hostname) */
    compute_user_ctx(username, out + LH_NONCE_LEN + sizeof(uint64_t));

    return 0;
}

/* ── lh_challenge_validate ───────────────────────────────── */

bool lh_challenge_validate(const uint8_t  challenge[LH_CHALLENGE_LEN],
                            const char    *username)
{
    /* Check timestamp freshness */
    uint64_t ts;
    memcpy(&ts, challenge + LH_NONCE_LEN, sizeof(uint64_t));

    uint64_t now = (uint64_t)time(NULL);
    uint64_t diff = (now >= ts) ? (now - ts) : (ts - now);
    if (diff > LH_CHALLENGE_TIMEOUT_S) return false;

    /* Check user-context hash */
    uint8_t expected[SHA256_DIGEST_LENGTH];
    compute_user_ctx(username, expected);

    const uint8_t *got = challenge + LH_NONCE_LEN + sizeof(uint64_t);
    /* Constant-time comparison to prevent timing side-channels */
    unsigned int mismatch = 0;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        mismatch |= (expected[i] ^ got[i]);
    return (mismatch == 0);
}

/* ── lh_challenge_get_nonce ──────────────────────────────── */

void lh_challenge_get_nonce(const uint8_t challenge[LH_CHALLENGE_LEN],
                             uint8_t       out[LH_NONCE_LEN])
{
    memcpy(out, challenge, LH_NONCE_LEN);
}

/* ── lh_challenge_get_timestamp ──────────────────────────── */

uint64_t lh_challenge_get_timestamp(const uint8_t challenge[LH_CHALLENGE_LEN])
{
    uint64_t ts;
    memcpy(&ts, challenge + LH_NONCE_LEN, sizeof(uint64_t));
    return ts;
}
