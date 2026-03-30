# LinuxHello – Architecture

## Overview

LinuxHello replaces password-based local login on modern Linux systems
with a device-bound public-key credential protected by TPM 2.0 hardware,
where biometrics or a PIN are used **only** to unlock the private key
locally.  The private key is non-exportable and bound to the device.

---

## A. Component Diagram

```
  ┌────────────────────────────────────────────────────────────────────┐
  │ User space                                                         │
  │                                                                    │
  │  ┌──────────────┐   PAM conversation   ┌──────────────────────┐   │
  │  │  Login / DM  │◄────────────────────►│  pam_linuxhello.so   │   │
  │  │  (GDM/SDDM/  │                      │  (PAM module)        │   │
  │  │   console)   │                      │  - pam_sm_authenticate│   │
  │  └──────────────┘                      │  - pam_sm_acct_mgmt  │   │
  │                                        └──────────┬───────────┘   │
  │                                                   │ Unix socket   │
  │                                                   │ /run/linuxhello│
  │                                         ┌─────────▼───────────┐   │
  │                                         │  lhd (auth daemon)  │   │
  │  ┌──────────────┐   D-Bus               │  running as root    │   │
  │  │   fprintd    │◄─────────────────────►│  - challenge gen    │   │
  │  │  (biometric  │  net.reactivated.     │  - gesture gate     │   │
  │  │   daemon)    │  Fprint               │  - TPM signing      │   │
  │  └──────────────┘                       │  - sig verification │   │
  │         │                               │  - lockout mgmt     │   │
  │         │ libfprint                     └─────────┬───────────┘   │
  │  ┌──────▼───────┐                                 │               │
  │  │  fingerprint │                        ┌────────▼────────┐      │
  │  │    reader    │                        │  lh-enroll CLI  │      │
  │  └──────────────┘                        │  (enrollment)   │      │
  │                                          └─────────────────┘      │
  │  ┌──────────────────────────────────────────────────────────────┐ │
  │  │  /var/lib/linuxhello/<user>/                                 │ │
  │  │    pubkey.der   – DER SubjectPublicKeyInfo (ECC P-256)       │ │
  │  │    meta.json    – key type, handle, enrollment timestamp     │ │
  │  │    lockout      – binary failed-attempt counter + timestamp  │ │
  │  │    privkey.enc  – (degraded mode only) AES-256-GCM encrypted │ │
  │  └──────────────────────────────────────────────────────────────┘ │
  └────────────────────────────────────────────────────────────────────┘

  ┌────────────────────────────────────────────────────────────────────┐
  │ Kernel / hardware                                                  │
  │                                                                    │
  │  ┌────────────────────────────────────────────────────────────┐   │
  │  │ TPM 2.0                                                     │   │
  │  │  Persistent key  0x8100xxxx  ECC P-256, fixedTPM|fixedParent│   │
  │  │  Policy: PolicyCommandCode(Sign) + PolicyAuthValue(PIN)    │   │
  │  │  NVRAM 0x0150xxxx  lockout counter (per-user, monotonic)   │   │
  │  │  DA lockout: hardware rate-limit after N bad PINs          │   │
  │  └────────────────────────────────────────────────────────────┘   │
  └────────────────────────────────────────────────────────────────────┘
```

### Permissions summary

| Path                               | Owner      | Mode  |
|------------------------------------|------------|-------|
| `/var/lib/linuxhello/`             | root:root  | 0700  |
| `/var/lib/linuxhello/<user>/`      | root:root  | 0700  |
| `/var/lib/linuxhello/<user>/pubkey.der` | root:root | 0600 |
| `/var/lib/linuxhello/<user>/meta.json`  | root:root | 0600 |
| `/var/lib/linuxhello/<user>/lockout`    | root:root | 0600 |
| `/run/linuxhello/`                 | root:root  | 0700  |
| `/run/linuxhello/auth.sock`        | root:root  | 0600  |

---

## B. Data Flows

### B1. Enrollment

```
Administrator / user (as root)
        │
        ▼
  lh-enroll enroll --user alice
        │
        ├─1─► Prompt PIN (no-echo terminal read)
        │
        ├─2─► lh_tpm_create_key(pin)
        │       │
        │       ▼
        │     TPM: Esys_Create(fixedTPM|fixedParent|sign, policy=PolicyAuthValue)
        │     TPM: Esys_Load → Esys_EvictControl → persistent handle 0x8100xxxx
        │     Returns: DER public key
        │
        ├─3─► lh_tpm_nv_init_counter()   # NVRAM lockout index
        │
        ├─4─► lh_storage_save_credential()  # pubkey.der + meta.json
        │
        └─5─► lh_bio_enroll()   (optional, via fprintd D-Bus)
```

### B2. Authentication

```
Login manager (e.g., GDM)
        │
        ▼
  PAM stack → pam_sm_authenticate
        │
        ├─1─► connect to /run/linuxhello/auth.sock
        │
        ├─2─► send LH_MSG_AUTH_REQUEST { username }
        │
        │                        lhd (daemon)
        │                               │
        │               ┌───────────────┤
        │               │ check lockout │
        │               │ load cred     │
        │               │ gen challenge │
        │               └───────────────┘
        │
        ├─3─► recv LH_MSG_CHALLENGE { 72-byte challenge }
        │
        │     [parallel: daemon triggers fprintd biometric verification]
        │
        ├─4─► prompt user: PIN (or inform to place finger)
        │
        ├─5─► send PIN (over local Unix socket)
        │
        │                        lhd
        │                               │
        │               ┌───────────────┤
        │               │ bio gate: OK? │
        │               │   OR          │
        │               │ PIN auth:     │
        │               │   policy sess │
        │               │   Esys_Sign   │
        │               └───────────────┘
        │
        ├─6─► [daemon verifies signature vs pubkey.der]
        │
        └─7─► recv LH_MSG_AUTH_RESULT { LH_OK | LH_ERR_BAD_SIG | ... }
                │
                ▼
          PAM_SUCCESS / PAM_AUTH_ERR
```

### B3. Credential Rotation

```
lh-enroll rotate --user alice
    │
    ├─1─► lh-enroll revoke  (delete TPM key, NVRAM counter, files)
    └─2─► lh-enroll enroll  (generate new key, new PIN, optionally re-enroll bio)
```

### B4. Recovery Paths

| Scenario                   | Recovery Action                                       |
|----------------------------|-------------------------------------------------------|
| Forgotten PIN              | Root runs `lh-enroll rotate --user <u>` to replace   |
| Biometric failure          | Fall back to PIN (PIN is always the backup gesture)   |
| TPM cleared                | Re-enroll: `lh-enroll rotate`; old key is gone        |
| Daemon not running         | PAM returns `PAM_IGNORE` → password fallback applies  |
| No enrolled credential     | PAM returns `PAM_IGNORE` → password fallback applies  |
| Account locked out         | Admin resets: `lh-enroll rotate --user <u>`           |
| Degraded mode + PIN lost   | Root deletes `/var/lib/linuxhello/<u>/` and re-enrolls|

---

## C. Cryptographic Design

### Key algorithm choice: ECC P-256 (NIST prime256v1)

| Criterion       | ECC P-256              | RSA-2048              |
|-----------------|------------------------|-----------------------|
| Security level  | ~128-bit               | ~112-bit              |
| Key size        | 32 bytes (private)     | 256 bytes (private)   |
| Sig size (DER)  | ≤72 bytes              | 256 bytes             |
| TPM requirement | Mandatory (TCG Part 2) | Mandatory (TCG Part 2)|
| IPC overhead    | Low                    | Higher                |
| OpenSSL support | Full                   | Full                  |

P-256 is the minimum required curve in TCG TPM 2.0 Part 2.  It provides
~128-bit security, which exceeds NIST recommendations through 2030+.

### Challenge format (72 bytes)

```
Offset  Length  Content
──────  ──────  ───────────────────────────────────────────────────────
0       32      CSPRNG nonce (256 bits of entropy from RAND_bytes)
32       8      uint64 Unix timestamp, little-endian
40      32      SHA-256(username || '\0' || hostname)
```

**Why:**
- Nonce prevents pre-computation of signatures
- Timestamp creates a 30-second replay window
- User+host context prevents cross-machine replay even if an attacker
  captures a valid signature from machine A and presents it on machine B

### Signing scheme

```
  digest = SHA-256(challenge[0..71])
  signature = ECDSA-P256-SHA256(private_key, digest)
```

Verification (in lhd, after receiving the signed challenge):
```
  verify ECDSA-P256-SHA256(pubkey_der, challenge[0..71], signature_der)
```

### Public key storage

The DER-encoded SubjectPublicKeyInfo is written to
`/var/lib/linuxhello/<user>/pubkey.der` (root:root 0600).
Its SHA-256 hash is stored in `meta.json` for integrity checking
(though an attacker with root access can modify both).

The public key is NOT a secret.  Its purpose is to allow the daemon
to verify signatures without access to the private key.

### TPM key creation details

```
TPM2B_PUBLIC template:
  type             = TPM2_ALG_ECC
  nameAlg          = TPM2_ALG_SHA256
  objectAttributes = fixedTPM            ← cannot migrate to another TPM
                   | fixedParent         ← cannot be re-parented
                   | sensitiveDataOrigin ← key generated on-chip
                   | userWithAuth        ← auth required
                   | sign               ← signing only (no decrypt)
  authPolicy       = PolicyCommandCode(TPM2_CC_Sign)
                   + PolicyAuthValue     ← PIN required in policy session
  parameters.eccDetail:
    symmetric = NULL (no symmetric wrapping)
    scheme    = ECDSA / SHA-256
    curveID   = TPM2_ECC_NIST_P256
```

The `fixedTPM + fixedParent` combination is what makes the key
non-exportable.  A `TPM2_CC_Duplicate` command would fail with
`TPM_RC_ATTRIBUTES`.

---

## D. TPM Policy & Local Gesture

### PIN gesture

1. During enrollment: a `TPM2_SE_TRIAL` policy session computes
   `PolicyDigest = H(PolicyCommandCode(Sign) || PolicyAuthValue)`.
   This digest is set as the key's `authPolicy`.

2. During authentication: a `TPM2_SE_POLICY` session replays
   the same policies; `PolicyAuthValue` requires the caller to provide
   the correct PIN as the key's `authValue`.

3. If the PIN is wrong, `Esys_Sign` returns `TPM_RC_AUTH_FAIL`.
   The TPM's internal DA counter increments.  After `TPM_PT_MAX_AUTH_FAIL`
   consecutive failures (set by the TPM manufacturer, typically 32),
   the TPM enters lockout mode (`TPM_RC_LOCKOUT`).  Recovery requires the
   TPM lockout authorization (usually cleared on reboot after a timeout).

### Biometric gesture

1. The daemon calls `fprintd.Device.Claim()` + `VerifyStart("any")`.
2. fprintd compares the scanned fingerprint against the enrolled template
   (stored inside libfprint / fprintd, NOT exposed to LinuxHello).
3. If the result is `verify-match`, the daemon proceeds to TPM signing.
4. The biometric result **does not** replace the PIN as a TPM authValue.
   In the current design the PIN is still required for the TPM policy
   session.  Future work: store a PIN-derived authValue in a sealed NVRAM
   credential that is released after biometric success.

### Lockout / rate-limiting (two layers)

| Layer            | Mechanism                              | Reset                     |
|------------------|----------------------------------------|---------------------------|
| Software counter | `/var/lib/linuxhello/<u>/lockout`      | `lh-enroll rotate`        |
| TPM NVRAM counter| NVRAM index 0x0150xxxx (monotonic)     | `lh-enroll rotate`        |
| TPM DA lockout   | TPM internal (hardware, mandatory)     | Reboot + wait / tpm2 clear|

Both the software counter and the TPM NVRAM counter track failed attempts.
The software counter imposes `LH_LOCKOUT_SECONDS` (300 s) after
`LH_MAX_ATTEMPTS` (5) failures.  The TPM DA lockout is an independent
hardware backstop.

---

## E. Degraded Mode (no TPM)

When no TPM 2.0 is detected, LinuxHello falls back to a software-protected
key:

```
Enrollment:
  EVP_PKEY_keygen(EC/prime256v1)
  key_material = AES-256-GCM(PBKDF2-SHA256(PIN, salt, 210000), iv, privkey_DER)
  Store: salt(16) || iv(12) || GCM-tag(16) || ciphertext

Authentication:
  Decrypt privkey with PIN → ECDSA-P256 sign → verify
```

**Stated risks:**
- Private key is on disk (even if encrypted); a root attacker can attempt
  offline brute-force against the PIN
- No hardware lockout; the software lockout can be bypassed by root
- The private key CAN be extracted with root + sufficient compute
- **Not equivalent to Windows Hello or TPM mode**
- Users must be explicitly warned during degraded-mode enrollment
