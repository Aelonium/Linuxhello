/*
 * storage.c – Secure credential storage implementation
 */

#include "storage.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include <openssl/sha.h>
#include <openssl/evp.h>

/* ── Helpers ─────────────────────────────────────────────── */

/* Create a directory with exact permissions; no-op if it exists */
static int mkdir_strict(const char *path, mode_t mode)
{
    if (mkdir(path, mode) == 0) return 0;
    if (errno == EEXIST)       return 0;
    return -1;
}

/* Write @len bytes from @buf to @path atomically (tmp + rename) */
static int write_file_atomic(const char *path,
                              const void *buf, size_t len,
                              mode_t mode)
{
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());

    int fd = open(tmp, O_WRONLY|O_CREAT|O_EXCL, mode);
    if (fd < 0) return -1;

    ssize_t written = write(fd, buf, len);
    close(fd);

    if (written < 0 || (size_t)written != len) {
        unlink(tmp);
        return -1;
    }
    if (rename(tmp, path) != 0) {
        unlink(tmp);
        return -1;
    }
    return 0;
}

/* Read the entire content of @path into a heap-allocated buffer */
static int read_file_alloc(const char *path, uint8_t **out, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    rewind(f);

    if (len <= 0) { fclose(f); return -1; }

    uint8_t *buf = malloc((size_t)len);
    if (!buf) { fclose(f); return -1; }

    if (fread(buf, 1, (size_t)len, f) != (size_t)len) {
        free(buf); fclose(f); return -1;
    }
    fclose(f);
    *out     = buf;
    *out_len = (size_t)len;
    return 0;
}

/* ── lh_storage_init ─────────────────────────────────────── */

int lh_storage_init(void)
{
    return mkdir_strict(LH_STATE_DIR, 0700);
}

/* ── lh_storage_save_credential ──────────────────────────── */

int lh_storage_save_credential(const lh_credential_t *cred)
{
    /* Create per-user directory */
    char user_dir[256];
    snprintf(user_dir, sizeof(user_dir), LH_USER_DIR_FMT, cred->username);
    if (mkdir_strict(user_dir, 0700) != 0) return -1;

    /* Write pubkey.der */
    char pubkey_path[256];
    snprintf(pubkey_path, sizeof(pubkey_path),
             LH_PUBKEY_FILE_FMT, cred->username);
    if (write_file_atomic(pubkey_path,
                          cred->pubkey_der, cred->pubkey_der_len,
                          0600) != 0)
        return -1;

    /* Write meta.json */
    char meta_path[256];
    snprintf(meta_path, sizeof(meta_path), LH_META_FILE_FMT, cred->username);

    char enrolled_ts[64];
    struct tm *tm_info = gmtime(&cred->enrolled_at);
    if (tm_info)
        strftime(enrolled_ts, sizeof(enrolled_ts), "%Y-%m-%dT%H:%M:%SZ", tm_info);
    else
        strncpy(enrolled_ts, "unknown", sizeof(enrolled_ts) - 1);

    /* Format pubkey SHA-256 as hex */
    char sha256_hex[65];
    for (int i = 0; i < 32; i++)
        snprintf(sha256_hex + 2*i, 3, "%02x", cred->pubkey_sha256[i]);

    char json[1024];
    int  json_len = snprintf(json, sizeof(json),
        "{\n"
        "  \"version\": 1,\n"
        "  \"username\": \"%s\",\n"
        "  \"key_type\": \"%s\",\n"
        "  \"tpm_available\": %s,\n"
        "  \"tpm_key_handle\": \"0x%08x\",\n"
        "  \"pubkey_sha256\": \"%s\",\n"
        "  \"enrolled_at\": \"%s\",\n"
        "  \"biometric\": \"%s\",\n"
        "  \"biometric_enrolled\": %s,\n"
        "  \"degraded_mode\": %s,\n"
        "  \"user_slot\": %u\n"
        "}\n",
        cred->username,
        cred->key_type,
        cred->tpm_available ? "true" : "false",
        cred->tpm_handle,
        sha256_hex,
        enrolled_ts,
        cred->biometric_type,
        cred->biometric_enrolled ? "true" : "false",
        cred->degraded_mode ? "true" : "false",
        cred->user_slot);

    if (json_len < 0 || (size_t)json_len >= sizeof(json)) return -1;
    return write_file_atomic(meta_path, json, (size_t)json_len, 0600);
}

/* ── lh_storage_load_credential ──────────────────────────── */

int lh_storage_load_credential(const char *username, lh_credential_t *out)
{
    memset(out, 0, sizeof(*out));
    strncpy(out->username, username, sizeof(out->username) - 1);

    /* Load pubkey.der */
    char pubkey_path[256];
    snprintf(pubkey_path, sizeof(pubkey_path), LH_PUBKEY_FILE_FMT, username);

    uint8_t *raw = NULL;
    size_t   raw_len = 0;
    if (read_file_alloc(pubkey_path, &raw, &raw_len) != 0)
        return LH_ERR_NO_CRED;

    if (raw_len > LH_PUBKEY_MAX_LEN) {
        free(raw);
        return LH_ERR_GENERIC;
    }
    memcpy(out->pubkey_der, raw, raw_len);
    out->pubkey_der_len = raw_len;
    free(raw);

    /* Compute and verify SHA-256 of the public key */
    SHA256(out->pubkey_der, out->pubkey_der_len, out->pubkey_sha256);

    /* Parse meta.json – minimal hand-rolled parser for the fields we need */
    char meta_path[256];
    snprintf(meta_path, sizeof(meta_path), LH_META_FILE_FMT, username);

    FILE *mf = fopen(meta_path, "r");
    if (!mf) return LH_ERR_NO_CRED;

    char line[512];
    while (fgets(line, sizeof(line), mf)) {
        unsigned int handle_u = 0;
        char val[256];
        unsigned int slot_u = 0;

        if (sscanf(line, " \"key_type\": \"%255[^\"]\"", val) == 1)
            strncpy(out->key_type, val, sizeof(out->key_type) - 1);
        else if (sscanf(line, " \"tpm_available\": %255s", val) == 1)
            out->tpm_available = (strcmp(val, "true,") == 0 ||
                                  strcmp(val, "true")  == 0);
        else if (sscanf(line, " \"tpm_key_handle\": \"0x%x\"", &handle_u) == 1)
            out->tpm_handle = handle_u;
        else if (sscanf(line, " \"biometric\": \"%255[^\"]\"", val) == 1)
            strncpy(out->biometric_type, val, sizeof(out->biometric_type) - 1);
        else if (sscanf(line, " \"biometric_enrolled\": %255s", val) == 1)
            out->biometric_enrolled = (strcmp(val, "true,") == 0 ||
                                       strcmp(val, "true")  == 0);
        else if (sscanf(line, " \"degraded_mode\": %255s", val) == 1)
            out->degraded_mode = (strcmp(val, "true,") == 0 ||
                                  strcmp(val, "true")  == 0);
        else if (sscanf(line, " \"user_slot\": %u", &slot_u) == 1)
            out->user_slot = slot_u;
    }
    fclose(mf);

    return LH_OK;
}

/* ── lh_storage_delete_credential ────────────────────────── */

int lh_storage_delete_credential(const char *username)
{
    char path[256];

    /* Remove individual files first */
    snprintf(path, sizeof(path), LH_PUBKEY_FILE_FMT, username);
    unlink(path);

    snprintf(path, sizeof(path), LH_META_FILE_FMT, username);
    unlink(path);

    snprintf(path, sizeof(path), LH_LOCKOUT_FILE_FMT, username);
    unlink(path);

    snprintf(path, sizeof(path), LH_DEGRADED_KEY_FILE_FMT, username);
    unlink(path);

    /* Remove the user directory */
    snprintf(path, sizeof(path), LH_USER_DIR_FMT, username);
    if (rmdir(path) != 0 && errno != ENOENT) return -1;
    return 0;
}

/* ── lh_storage_credential_exists ────────────────────────── */

bool lh_storage_credential_exists(const char *username)
{
    char pubkey_path[256];
    snprintf(pubkey_path, sizeof(pubkey_path), LH_PUBKEY_FILE_FMT, username);
    return access(pubkey_path, F_OK) == 0;
}

/* ── Lockout state ───────────────────────────────────────── */

/*
 * lockout file layout (binary, 12 bytes):
 *   uint32_t failed_attempts  (little-endian)
 *   int64_t  last_failure     (Unix seconds, little-endian)
 */
#define LOCKOUT_FILE_SIZE 12

int lh_storage_load_lockout(const char *username, lh_lockout_t *out)
{
    memset(out, 0, sizeof(*out));

    char path[256];
    snprintf(path, sizeof(path), LH_LOCKOUT_FILE_FMT, username);

    int fd = open(path, O_RDONLY);
    if (fd < 0) return 0; /* no lockout file → zero state */

    uint8_t buf[LOCKOUT_FILE_SIZE];
    ssize_t n = read(fd, buf, sizeof(buf));
    close(fd);
    if (n != LOCKOUT_FILE_SIZE) return 0;

    uint32_t attempts;
    int64_t  ts;
    memcpy(&attempts, buf,     4);
    memcpy(&ts,       buf + 4, 8);

    out->failed_attempts = attempts;
    out->last_failure    = (time_t)ts;
    out->locked          = lh_storage_check_lockout(out);
    return 0;
}

int lh_storage_save_lockout(const char *username, const lh_lockout_t *lock)
{
    char path[256];
    snprintf(path, sizeof(path), LH_LOCKOUT_FILE_FMT, username);

    uint8_t buf[LOCKOUT_FILE_SIZE];
    uint32_t attempts = lock->failed_attempts;
    int64_t  ts       = (int64_t)lock->last_failure;
    memcpy(buf,     &attempts, 4);
    memcpy(buf + 4, &ts,       8);

    return write_file_atomic(path, buf, sizeof(buf), 0600);
}

bool lh_storage_check_lockout(lh_lockout_t *lock)
{
    if (!lock->locked) {
        /* Auto-unlock after LH_LOCKOUT_SECONDS */
        if (lock->failed_attempts >= LH_MAX_ATTEMPTS) {
            time_t now    = time(NULL);
            time_t unlock = lock->last_failure + LH_LOCKOUT_SECONDS;
            if (now < unlock) {
                lock->locked = true;
                return true;
            }
            /* Lockout expired – reset counter */
            lock->failed_attempts = 0;
            lock->locked          = false;
        }
    }
    return lock->locked;
}

int lh_storage_record_failure(const char *username)
{
    lh_lockout_t lock;
    lh_storage_load_lockout(username, &lock);

    lock.failed_attempts++;
    lock.last_failure = time(NULL);

    if (lock.failed_attempts >= LH_MAX_ATTEMPTS)
        lock.locked = true;

    return lh_storage_save_lockout(username, &lock);
}

int lh_storage_reset_lockout(const char *username)
{
    lh_lockout_t lock = { 0 };
    return lh_storage_save_lockout(username, &lock);
}
