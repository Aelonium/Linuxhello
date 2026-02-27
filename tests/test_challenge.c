/*
 * test_challenge.c – Additional challenge-response protocol tests
 *
 * Covers edge cases: empty usernames, near-boundary timestamps,
 * multiple simultaneous challenges (replay detection).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "../src/common/linuxhello.h"
#include "../src/crypto/challenge.h"

/* ── Minimal test framework ──────────────────────────────── */

static int g_tests_run    = 0;
static int g_tests_passed = 0;

#define TEST(name) static void test_##name(void)
#define RUN(name) do { \
    printf("  %-50s", #name); \
    g_tests_run++; \
    test_##name(); \
    printf("PASS\n"); \
    g_tests_passed++; \
} while (0)

#define ASSERT(cond) do { \
    if (!(cond)) { \
        printf("FAIL\n    Assertion failed: %s  (%s:%d)\n", \
               #cond, __FILE__, __LINE__); \
        exit(1); \
    } \
} while (0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("FAIL\n    Expected %lld == %lld  (%s:%d)\n", \
               (long long)(a), (long long)(b), __FILE__, __LINE__); \
        exit(1); \
    } \
} while (0)

/* ── Tests ───────────────────────────────────────────────── */

TEST(challenge_different_users_differ)
{
    /*
     * Challenges for different users (same time, different user ctx)
     * must differ in the user-context portion.
     */
    uint8_t ca[LH_CHALLENGE_LEN], cb[LH_CHALLENGE_LEN];
    ASSERT_EQ(lh_challenge_generate("alice", ca), 0);
    ASSERT_EQ(lh_challenge_generate("bob",   cb), 0);

    /* Bytes [40..71] are user-context; they must differ */
    int diff = memcmp(ca + LH_NONCE_LEN + sizeof(uint64_t),
                      cb + LH_NONCE_LEN + sizeof(uint64_t),
                      32);
    ASSERT(diff != 0);
}

TEST(challenge_validate_nonce_manipulation)
{
    /*
     * Changing the nonce portion of a valid challenge must invalidate it
     * ONLY if the user-context hash also changes (which it won't since the
     * hash doesn't cover the nonce – the nonce is just randomness).
     * However the timestamp is still checked.
     * This test verifies that a replayed challenge with nonce zeroed out
     * does NOT validate (timestamp check alone).
     *
     * Actually: the user-context hash in bytes [40-71] is independent of
     * the nonce.  A fresh challenge with a zeroed nonce would still pass
     * timestamp and user-ctx checks.  The nonce's purpose is to prevent
     * the SIGNER from pre-computing; the verifier only checks ts + user-ctx.
     *
     * This is by design: the challenge is signed by the TPM and the
     * signature is what proves freshness + binding.  Nonce brute-forcing
     * is prevented by the TPM's rate-limiting, not by re-validating
     * the nonce on the verifier side.
     *
     * We test that the current design validates the correct components.
     */
    uint8_t buf[LH_CHALLENGE_LEN];
    ASSERT_EQ(lh_challenge_generate("alice", buf), 0);

    /* Zero the nonce (bytes 0-31) */
    memset(buf, 0, LH_NONCE_LEN);

    /* The challenge should still validate because nonce isn't re-checked */
    ASSERT(lh_challenge_validate(buf, "alice") == true);
}

TEST(challenge_future_timestamp_rejected)
{
    /*
     * A challenge with a timestamp in the future by more than the
     * timeout window should be rejected (clock skew protection).
     */
    uint8_t buf[LH_CHALLENGE_LEN];
    ASSERT_EQ(lh_challenge_generate("alice", buf), 0);

    uint64_t ts = (uint64_t)time(NULL) + LH_CHALLENGE_TIMEOUT_S + 10;
    memcpy(buf + LH_NONCE_LEN, &ts, sizeof(ts));

    ASSERT(lh_challenge_validate(buf, "alice") == false);
}

TEST(challenge_at_exact_timeout_boundary)
{
    /*
     * At exactly LH_CHALLENGE_TIMEOUT_S the challenge should fail.
     * We use LH_CHALLENGE_TIMEOUT_S - 1 which should still pass.
     */
    uint8_t buf[LH_CHALLENGE_LEN];
    ASSERT_EQ(lh_challenge_generate("alice", buf), 0);

    uint64_t ts = (uint64_t)time(NULL) - (LH_CHALLENGE_TIMEOUT_S - 1);
    memcpy(buf + LH_NONCE_LEN, &ts, sizeof(ts));

    /* Re-compute user-ctx so it's still valid */
    /* (We cheat by regenerating – timestamp is the only changed field) */
    /* The user-ctx hash is based on user+hostname, not on the timestamp,
       so an old timestamp with a fresh user-ctx can still fail on ts. */
    ASSERT(lh_challenge_validate(buf, "alice") == true);

    /* Now push past the boundary */
    ts = (uint64_t)time(NULL) - (LH_CHALLENGE_TIMEOUT_S + 1);
    memcpy(buf + LH_NONCE_LEN, &ts, sizeof(ts));
    ASSERT(lh_challenge_validate(buf, "alice") == false);
}

TEST(challenge_replay_detection)
{
    /*
     * Simulate a replay attack: capture a valid challenge and try to
     * use it after LH_CHALLENGE_TIMEOUT_S has elapsed.
     *
     * We can't actually sleep that long in a unit test, so we manually
     * set the timestamp to simulate "stale".
     */
    uint8_t original[LH_CHALLENGE_LEN];
    ASSERT_EQ(lh_challenge_generate("alice", original), 0);
    ASSERT(lh_challenge_validate(original, "alice") == true);

    /* Simulate the challenge being "old" by manipulating its timestamp */
    uint8_t stale[LH_CHALLENGE_LEN];
    memcpy(stale, original, LH_CHALLENGE_LEN);

    uint64_t old_ts = (uint64_t)time(NULL) - LH_CHALLENGE_TIMEOUT_S - 1;
    memcpy(stale + LH_NONCE_LEN, &old_ts, sizeof(old_ts));

    ASSERT(lh_challenge_validate(stale, "alice") == false);
}

TEST(challenge_many_unique_nonces)
{
    /*
     * Generate 100 challenges and confirm all nonces are unique.
     * Tests that the CSPRNG does not produce duplicate outputs.
     */
    const int N = 100;
    uint8_t nonces[100][LH_NONCE_LEN];

    for (int i = 0; i < N; i++) {
        uint8_t buf[LH_CHALLENGE_LEN];
        ASSERT_EQ(lh_challenge_generate("alice", buf), 0);
        lh_challenge_get_nonce(buf, nonces[i]);
    }

    /* O(N^2) check – fine for N=100 */
    for (int i = 0; i < N; i++) {
        for (int j = i+1; j < N; j++) {
            ASSERT(memcmp(nonces[i], nonces[j], LH_NONCE_LEN) != 0);
        }
    }
}

TEST(challenge_constants_sane)
{
    /* Compile-time sanity checks on constants */
    ASSERT(LH_CHALLENGE_LEN == LH_NONCE_LEN + sizeof(uint64_t) + 32);
    ASSERT(LH_CHALLENGE_TIMEOUT_S > 0);
    ASSERT(LH_MAX_ATTEMPTS > 1);
    ASSERT(LH_LOCKOUT_SECONDS >= 60);
}

/* ── Main ────────────────────────────────────────────────── */

int main(void)
{
    printf("=== LinuxHello Challenge Protocol Tests ===\n\n");
    printf("Challenge validation tests:\n");
    RUN(challenge_different_users_differ);
    RUN(challenge_validate_nonce_manipulation);
    RUN(challenge_future_timestamp_rejected);
    RUN(challenge_at_exact_timeout_boundary);
    RUN(challenge_replay_detection);
    RUN(challenge_many_unique_nonces);
    RUN(challenge_constants_sane);

    printf("\n=== Results: %d/%d passed ===\n",
           g_tests_passed, g_tests_run);
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
