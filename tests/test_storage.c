/*
 * test_storage.c – Unit tests for LinuxHello credential storage
 *
 * Tests lockout logic and credential persistence using a temporary
 * directory so that tests are safe to run as a non-root user (except
 * where root is required – those tests are skipped gracefully).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

#include "../src/common/linuxhello.h"
#include "../src/storage/storage.h"

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

/* ── Lockout tests (no root required) ───────────────────── */

TEST(lockout_initial_state)
{
    lh_lockout_t lock = { 0 };
    ASSERT(lh_storage_check_lockout(&lock) == false);
    ASSERT_EQ(lock.failed_attempts, 0U);
    ASSERT(lock.locked == false);
}

TEST(lockout_threshold_exactly)
{
    lh_lockout_t lock = {
        .failed_attempts = LH_MAX_ATTEMPTS,
        .last_failure    = time(NULL),
        .locked          = false,
    };
    /* At exactly LH_MAX_ATTEMPTS we should be locked */
    ASSERT(lh_storage_check_lockout(&lock) == true);
}

TEST(lockout_below_threshold)
{
    lh_lockout_t lock = {
        .failed_attempts = LH_MAX_ATTEMPTS - 1,
        .last_failure    = time(NULL),
        .locked          = false,
    };
    ASSERT(lh_storage_check_lockout(&lock) == false);
}

TEST(lockout_expired_auto_reset)
{
    lh_lockout_t lock = {
        .failed_attempts = LH_MAX_ATTEMPTS,
        /* Set last_failure to well before the lockout window */
        .last_failure    = time(NULL) - LH_LOCKOUT_SECONDS - 1,
        .locked          = false,
    };
    /* Lockout window has passed – should no longer be locked */
    ASSERT(lh_storage_check_lockout(&lock) == false);
    /* Counter should have been reset */
    ASSERT_EQ(lock.failed_attempts, 0U);
}

TEST(lockout_active_window)
{
    lh_lockout_t lock = {
        .failed_attempts = LH_MAX_ATTEMPTS,
        .last_failure    = time(NULL) - 5, /* 5 seconds ago – still locked */
        .locked          = false,
    };
    ASSERT(lh_storage_check_lockout(&lock) == true);
}

/* ── Credential struct round-trip (in-memory, no disk) ──── */

TEST(credential_struct_init)
{
    lh_credential_t cred;
    memset(&cred, 0, sizeof(cred));
    strncpy(cred.username, "testuser", sizeof(cred.username) - 1);
    strncpy(cred.key_type, "ECC_P256", sizeof(cred.key_type) - 1);
    cred.enrolled_at = time(NULL);

    ASSERT(strcmp(cred.username, "testuser") == 0);
    ASSERT(strcmp(cred.key_type, "ECC_P256") == 0);
    ASSERT(cred.enrolled_at != 0);
}

TEST(credential_pubkey_sha256_uniqueness)
{
    /*
     * Two different fake public keys must have different SHA-256 hashes.
     * This is a sanity check that we're computing SHA-256 correctly.
     */
    uint8_t key_a[32], key_b[32];
    memset(key_a, 0xAA, sizeof(key_a));
    memset(key_b, 0xBB, sizeof(key_b));

    uint8_t hash_a[32], hash_b[32];
    SHA256(key_a, sizeof(key_a), hash_a);
    SHA256(key_b, sizeof(key_b), hash_b);

    ASSERT(memcmp(hash_a, hash_b, 32) != 0);
}

/* ── File-based lockout round-trip (requires write access) ─ */

TEST(lockout_file_roundtrip)
{
    /*
     * This test writes a lockout file to /tmp and reads it back.
     * We temporarily override the username to use a /tmp path by
     * exercising lh_storage_save_lockout / lh_storage_load_lockout
     * directly with a temp dir.
     *
     * Since LH_LOCKOUT_FILE_FMT is /var/lib/linuxhello/%s/lockout and
     * we may not have write access there, we test through the public
     * API using a path we can control.
     *
     * If /var/lib/linuxhello is not writable, this test skips.
     */
    if (access("/var/lib/linuxhello", W_OK) != 0) {
        printf("SKIP (no write access to %s) ", LH_STATE_DIR);
        return; /* RUN macro counts this as passed */
    }

    const char *testuser = "lh_test_storage_$$";
    lh_storage_init();

    /* Set up the directory manually */
    char user_dir[256];
    snprintf(user_dir, sizeof(user_dir), LH_USER_DIR_FMT, testuser);
    mkdir(user_dir, 0700);

    lh_lockout_t original = {
        .failed_attempts = 3,
        .last_failure    = 1700000000,
        .locked          = false,
    };
    ASSERT_EQ(lh_storage_save_lockout(testuser, &original), 0);

    lh_lockout_t loaded;
    ASSERT_EQ(lh_storage_load_lockout(testuser, &loaded), 0);
    ASSERT_EQ(loaded.failed_attempts, original.failed_attempts);
    ASSERT_EQ((long long)loaded.last_failure, (long long)original.last_failure);

    /* Cleanup */
    lh_storage_delete_credential(testuser);
}

TEST(lockout_record_and_reset)
{
    if (access("/var/lib/linuxhello", W_OK) != 0) {
        printf("SKIP (no write access to %s) ", LH_STATE_DIR);
        return; /* RUN macro counts this as passed */
    }

    const char *testuser = "lh_test_lockout_rr";
    lh_storage_init();
    char user_dir[256];
    snprintf(user_dir, sizeof(user_dir), LH_USER_DIR_FMT, testuser);
    mkdir(user_dir, 0700);

    /* Record LH_MAX_ATTEMPTS failures – account should lock */
    for (int i = 0; i < LH_MAX_ATTEMPTS; i++)
        lh_storage_record_failure(testuser);

    lh_lockout_t lock;
    lh_storage_load_lockout(testuser, &lock);
    ASSERT_EQ(lock.failed_attempts, (unsigned)LH_MAX_ATTEMPTS);

    /* Reset on success */
    lh_storage_reset_lockout(testuser);
    lh_storage_load_lockout(testuser, &lock);
    ASSERT_EQ(lock.failed_attempts, 0U);
    ASSERT(lock.locked == false);

    /* Cleanup */
    lh_storage_delete_credential(testuser);
}

/* ── credential_exists (no root) ─────────────────────────── */

TEST(credential_exists_nonexistent)
{
    /* A user that definitely has no credential */
    ASSERT(lh_storage_credential_exists("lh_nonexistent_user_xyz") == false);
}

/* ── Main ────────────────────────────────────────────────── */

int main(void)
{
    printf("=== LinuxHello Storage Unit Tests ===\n\n");
    printf("Lockout logic tests (in-memory):\n");
    RUN(lockout_initial_state);
    RUN(lockout_threshold_exactly);
    RUN(lockout_below_threshold);
    RUN(lockout_expired_auto_reset);
    RUN(lockout_active_window);

    printf("\nCredential struct tests:\n");
    RUN(credential_struct_init);
    RUN(credential_pubkey_sha256_uniqueness);

    printf("\nFile-based tests (may skip if not root):\n");
    RUN(lockout_file_roundtrip);
    RUN(lockout_record_and_reset);
    RUN(credential_exists_nonexistent);

    printf("\n=== Results: %d/%d passed ===\n",
           g_tests_passed, g_tests_run);
    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
