/*
 * linuxhello.h – Shared constants, types, and IPC protocol definitions
 *
 * Linux Hello: device-bound public-key local authentication
 * (conceptually analogous to Windows Hello for local accounts)
 *
 * Security model:
 *   - Asymmetric key pair generated inside TPM (non-exportable)
 *   - Private key never leaves TPM protection boundary
 *   - Authentication via challenge–response: daemon generates nonce,
 *     TPM signs it, PAM verifies signature against stored public key
 *   - Biometrics/PIN used only as a local "unlock gesture" – never
 *     transmitted and never used as a shared secret
 */

#ifndef LINUXHELLO_H
#define LINUXHELLO_H

#include <stdint.h>
#include <stddef.h>

/* ── Version ─────────────────────────────────────────────── */
#define LH_VERSION_MAJOR  0
#define LH_VERSION_MINOR  1
#define LH_VERSION_PATCH  0

/* ── File-system paths ───────────────────────────────────── */
/** Root of all persistent LinuxHello state (root:root, mode 0700) */
#define LH_STATE_DIR          "/var/lib/linuxhello"
/** Per-user credential directory: LH_STATE_DIR/<username>/ */
#define LH_USER_DIR_FMT       LH_STATE_DIR "/%s"
/** Public key (raw DER-encoded SubjectPublicKeyInfo) */
#define LH_PUBKEY_FILE_FMT    LH_STATE_DIR "/%s/pubkey.der"
/** JSON metadata: key handle, creation data, PCR binding, enroll ts */
#define LH_META_FILE_FMT      LH_STATE_DIR "/%s/meta.json"
/** Lockout counter – incremented in TPM NVRAM; also a software shadow */
#define LH_LOCKOUT_FILE_FMT   LH_STATE_DIR "/%s/lockout"
/** Unix domain socket the auth daemon listens on */
#define LH_DAEMON_SOCKET      "/run/linuxhello/auth.sock"
/** PID file for the daemon */
#define LH_DAEMON_PID         "/run/linuxhello/lhd.pid"

/* ── Cryptographic parameters ────────────────────────────── */
/**
 * ECC P-256 (NIST prime256v1) chosen over RSA-2048 because:
 *   - Shorter keys/signatures → smaller PAM IPC messages
 *   - Mandatory in TCG TPM 2.0 Part 2 (ECC_NIST_P256 is required)
 *   - Equivalent security (~128-bit) to RSA-3072 at lower cost
 *   - ECDSA P-256 with SHA-256 is well-audited and ubiquitous
 */
#define LH_KEY_CURVE          "prime256v1"    /* OpenSSL NID name        */
#define LH_TPM_CURVE          TPM2_ECC_NIST_P256
#define LH_HASH_ALG           TPM2_ALG_SHA256
#define LH_SIG_SCHEME         TPM2_ALG_ECDSA

/** Raw challenge size in bytes (nonce || timestamp || user-ctx) */
#define LH_NONCE_LEN          32   /* bytes of CSPRNG randomness        */
#define LH_CHALLENGE_LEN      72   /* nonce(32) + ts(8) + user_ctx(32)  */
/** Maximum ECDSA P-256 DER signature size */
#define LH_SIG_MAX_LEN        72

/** Maximum public key DER size for P-256 SubjectPublicKeyInfo */
#define LH_PUBKEY_MAX_LEN     91

/* ── Rate-limiting / lockout ─────────────────────────────── */
/**
 * Failed-attempt threshold before the credential is soft-locked.
 * When a TPM is present the TPM dictionary-attack lockout (DA) also
 * applies independently; this counter is the software layer.
 */
#define LH_MAX_ATTEMPTS       5
/** Lockout duration in seconds after LH_MAX_ATTEMPTS failures */
#define LH_LOCKOUT_SECONDS    300   /* 5 minutes                        */

/* ── IPC message types ───────────────────────────────────── */
typedef enum lh_msg_type {
    LH_MSG_AUTH_REQUEST   = 0x01, /* PAM → daemon: start auth          */
    LH_MSG_CHALLENGE      = 0x02, /* daemon → PAM: here is the nonce   */
    LH_MSG_SIGNATURE      = 0x03, /* PAM → daemon: signed challenge     */
    LH_MSG_AUTH_RESULT    = 0x04, /* daemon → PAM: success / failure    */
    LH_MSG_ENROLL_REQUEST = 0x10, /* CLI → daemon: enroll user          */
    LH_MSG_ENROLL_RESULT  = 0x11, /* daemon → CLI: enroll outcome       */
    LH_MSG_REVOKE_REQUEST = 0x12, /* CLI → daemon: remove credential    */
    LH_MSG_REVOKE_RESULT  = 0x13, /* daemon → CLI: revoke outcome       */
} lh_msg_type_t;

/** Result codes returned in LH_MSG_AUTH_RESULT / LH_MSG_ENROLL_RESULT */
typedef enum lh_result {
    LH_OK             = 0,
    LH_ERR_GENERIC    = 1,
    LH_ERR_NO_CRED    = 2,   /* user has no enrolled credential       */
    LH_ERR_BAD_SIG    = 3,   /* signature verification failed         */
    LH_ERR_LOCKED     = 4,   /* account locked out (rate limit)       */
    LH_ERR_BIOMETRIC  = 5,   /* biometric verification failed/timeout */
    LH_ERR_TPM        = 6,   /* TPM operation failed                  */
    LH_ERR_PERM       = 7,   /* permission / policy error             */
    LH_ERR_REPLAY     = 8,   /* stale / replayed challenge            */
} lh_result_t;

/* ── Wire-format structs (all fields network byte order / little-endian
 *    clearly stated in each comment) ─────────────────────────────── */

#pragma pack(push, 1)

/** Header prepended to every IPC message */
typedef struct lh_msg_hdr {
    uint8_t  type;       /* lh_msg_type_t                             */
    uint16_t length;     /* total message size including this header  */
    uint8_t  reserved;
} lh_msg_hdr_t;

/** PAM → daemon: request authentication for username */
typedef struct lh_auth_request {
    lh_msg_hdr_t hdr;
    char username[64];   /* NUL-terminated, max 63 chars              */
} lh_auth_request_t;

/**
 * daemon → PAM: challenge to sign
 *
 * Challenge layout (72 bytes):
 *   [0..31]  32-byte CSPRNG nonce (generated by daemon)
 *   [32..39]  uint64_t Unix timestamp (seconds, little-endian)
 *             → PAM must reject if |now - ts| > LH_CHALLENGE_TIMEOUT_S
 *   [40..71] SHA-256(username || hostname)
 *             → Binds the challenge to the specific user+machine so a
 *               signature captured for user A on machine X cannot be
 *               replayed for user B or on machine Y.
 */
#define LH_CHALLENGE_TIMEOUT_S  30   /* seconds; guards replay window  */

typedef struct lh_challenge_msg {
    lh_msg_hdr_t hdr;
    uint8_t challenge[LH_CHALLENGE_LEN];
} lh_challenge_msg_t;

/** daemon → PAM: final authentication result */
typedef struct lh_auth_result_msg {
    lh_msg_hdr_t hdr;
    uint8_t result;      /* lh_result_t                               */
    uint8_t attempts;    /* remaining attempts before lockout         */
} lh_auth_result_msg_t;

#pragma pack(pop)

/* ── Credential metadata (written to LH_META_FILE_FMT as JSON) ───── */
/**
 * Fields stored per-user:
 *   "version"        : int
 *   "username"       : string
 *   "key_type"       : "ECC_P256"
 *   "tpm_available"  : bool
 *   "tpm_key_handle" : hex string  (TPM persistent handle, e.g. "0x81000001")
 *   "pubkey_sha256"  : hex string  (SHA-256 of stored pubkey.der)
 *   "enrolled_at"    : ISO-8601 timestamp
 *   "biometric"      : "fingerprint" | "none"
 *   "pcr_policy"     : array of PCR index/value pairs (if TPM sealing used)
 *   "degraded_mode"  : bool        (true iff no TPM; software key)
 */

/* ── Degraded mode (no TPM) ──────────────────────────────── */
/**
 * When no TPM 2.0 is available LinuxHello can operate in a "degraded"
 * software-only mode:
 *
 *   RISK TRADEOFFS vs TPM mode:
 *   - Private key stored encrypted on disk (AES-256-GCM) under a
 *     key derived from the PIN via PBKDF2-SHA256 (high iteration count).
 *   - A PIN brute-force by a root attacker is feasible if rate limiting
 *     is defeated; there is no hardware lockout.
 *   - The private key CAN be extracted by a root attacker with sufficient
 *     effort (unlike TPM mode where the key never leaves the chip).
 *   - Users should be warned; degraded mode should be disabled by policy
 *     on high-security systems.
 *
 *   Degraded mode is explicitly NOT equivalent to Windows Hello.
 *   It is provided only as a compatibility fallback.
 */
#define LH_DEGRADED_KEY_ITER   210000  /* PBKDF2 iterations (OWASP 2023) */
#define LH_DEGRADED_KEY_FILE_FMT  LH_STATE_DIR "/%s/privkey.enc"

#endif /* LINUXHELLO_H */
