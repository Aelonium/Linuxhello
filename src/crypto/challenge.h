/*
 * challenge.h – Challenge generation and validation for LinuxHello
 *
 * Challenge format (LH_CHALLENGE_LEN = 72 bytes):
 *   [0..31]   32-byte CSPRNG nonce
 *   [32..39]  uint64_t Unix timestamp, little-endian
 *   [40..71]  SHA-256(username || '\0' || hostname)
 *
 * The user-context hash (bytes 40-71) binds the challenge to a specific
 * user on a specific machine, preventing cross-machine replay even if an
 * attacker captures a valid signature from machine A and tries it on B.
 *
 * The timestamp provides a replay window: verifiers MUST reject any
 * challenge where |now - ts| > LH_CHALLENGE_TIMEOUT_S.
 */

#ifndef CHALLENGE_H
#define CHALLENGE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "../common/linuxhello.h"

/**
 * lh_challenge_generate – Create a fresh challenge for @username.
 *
 * @param username   NUL-terminated username string
 * @param out        Buffer of at least LH_CHALLENGE_LEN bytes
 *
 * Returns 0 on success, -1 on CSPRNG failure.
 */
int lh_challenge_generate(const char *username, uint8_t out[LH_CHALLENGE_LEN]);

/**
 * lh_challenge_validate – Verify that a challenge is fresh and well-formed.
 *
 * Checks:
 *   1. Timestamp is within LH_CHALLENGE_TIMEOUT_S seconds of now
 *   2. User-context hash matches SHA-256(username || '\0' || hostname)
 *
 * Returns true iff the challenge is valid for the current user/machine/time.
 */
bool lh_challenge_validate(const uint8_t  challenge[LH_CHALLENGE_LEN],
                            const char    *username);

/**
 * lh_challenge_get_nonce – Extract the 32-byte nonce from a challenge.
 * Writes to @out (must be at least 32 bytes).
 */
void lh_challenge_get_nonce(const uint8_t challenge[LH_CHALLENGE_LEN],
                             uint8_t       out[LH_NONCE_LEN]);

/**
 * lh_challenge_get_timestamp – Extract the Unix timestamp from a challenge.
 */
uint64_t lh_challenge_get_timestamp(const uint8_t challenge[LH_CHALLENGE_LEN]);

#endif /* CHALLENGE_H */
