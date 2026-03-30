# LinuxHello – Test Plan

## G. Test Plan

### G1. Unit Tests for Cryptographic Primitives

File: `tests/test_crypto.c`

| Test ID    | Description                                     | Expected              |
|------------|-------------------------------------------------|-----------------------|
| TC-CR-01   | Challenge is exactly 72 bytes                   | PASS                  |
| TC-CR-02   | Nonce portion is non-zero (CSPRNG works)        | PASS                  |
| TC-CR-03   | Fresh challenge validates correctly             | true                  |
| TC-CR-04   | Challenge invalid for wrong username            | false                 |
| TC-CR-05   | Challenge with backdated timestamp rejected     | false                 |
| TC-CR-06   | Challenge with tampered user-ctx hash rejected  | false                 |
| TC-CR-07   | Extracted timestamp matches generation time     | diff < 5 seconds      |
| TC-CR-08   | Two challenges have unique nonces               | memcmp ≠ 0            |
| TC-CR-09   | Sign + verify round-trip succeeds               | LH_OK                 |
| TC-CR-10   | Tampered signature fails verification           | LH_ERR_BAD_SIG        |
| TC-CR-11   | Signature from key A fails against key B's pubkey | LH_ERR_BAD_SIG     |

File: `tests/test_challenge.c`

| Test ID    | Description                                     | Expected              |
|------------|-------------------------------------------------|-----------------------|
| TC-CH-01   | Challenges for different users have different user-ctx | differ in bytes 40-71 |
| TC-CH-02   | Future timestamp (> timeout) rejected           | false                 |
| TC-CH-03   | Timestamp at boundary - 1 passes               | true                  |
| TC-CH-04   | Timestamp at boundary + 1 fails                | false                 |
| TC-CH-05   | Stale challenge (simulated replay) rejected     | false                 |
| TC-CH-06   | 100 challenges have unique nonces               | all unique            |
| TC-CH-07   | Compile-time constants are internally consistent | pass                 |

### G2. Unit Tests for Storage

File: `tests/test_storage.c`

| Test ID    | Description                                     | Expected              |
|------------|-------------------------------------------------|-----------------------|
| TC-ST-01   | Initial lockout state: no failure, not locked   | attempts=0, locked=false |
| TC-ST-02   | At LH_MAX_ATTEMPTS failures → locked            | locked=true           |
| TC-ST-03   | LH_MAX_ATTEMPTS - 1 failures → not locked       | locked=false          |
| TC-ST-04   | Lockout auto-expires after LH_LOCKOUT_SECONDS   | locked=false, count=0 |
| TC-ST-05   | Lockout active within window                    | locked=true           |
| TC-ST-06   | Credential struct initialises correctly         | PASS                  |
| TC-ST-07   | Two distinct keys have distinct SHA-256 hashes  | PASS                  |
| TC-ST-08   | Lockout file write + read round-trip            | values preserved      |
| TC-ST-09   | Record N failures → locked; reset → count=0    | PASS                  |
| TC-ST-10   | `credential_exists` returns false for unknown user | false              |

### G3. Integration Tests for PAM

These tests require a test environment (VM or container) with:
- LinuxHello daemon running
- A test user enrolled

| Test ID    | Description                                     | Expected              |
|------------|-------------------------------------------------|-----------------------|
| TI-PA-01   | Correct PIN → PAM_SUCCESS                       | PAM_SUCCESS           |
| TI-PA-02   | Wrong PIN (once) → PAM_IGNORE (fallback mode)   | PAM_IGNORE            |
| TI-PA-03   | 5 wrong PINs → PAM_MAXTRIES + account locked    | PAM_MAXTRIES          |
| TI-PA-04   | User with no credential → PAM_IGNORE            | PAM_IGNORE            |
| TI-PA-05   | Daemon not running → PAM_IGNORE                 | PAM_IGNORE (or AUTHINFO_UNAVAIL) |
| TI-PA-06   | nofallback + wrong PIN → PAM_AUTH_ERR           | PAM_AUTH_ERR          |
| TI-PA-07   | pam_sm_acct_mgmt with enrolled user → PAM_SUCCESS | PAM_SUCCESS         |
| TI-PA-08   | pam_sm_acct_mgmt with non-enrolled user → PAM_IGNORE | PAM_IGNORE       |
| TI-PA-09   | Biometric success → PAM_SUCCESS (no PIN entered) | PAM_SUCCESS          |
| TI-PA-10   | Biometric fail → PIN fallback → PAM_SUCCESS     | PAM_SUCCESS           |

### G4. Threat / Adversarial Tests

| Test ID    | Description                                     | Expected              |
|------------|-------------------------------------------------|-----------------------|
| TA-01      | **Brute force:** Script 5 rapid failed PIN attempts | Account locks after 5 |
| TA-02      | **Replay:** Capture valid auth exchange; replay after >30s | Rejected (stale challenge) |
| TA-03      | **Replay within window:** Capture + replay within 30s, different connection | Second attempt fails (each challenge is unique) |
| TA-04      | **TPM cleared:** Clear TPM NV; verify user cannot authenticate | Auth fails, rotation required |
| TA-05      | **pubkey.der replaced:** Replace with attacker's pubkey.der | Auth succeeds with attacker key (root attacker) – document residual risk |
| TA-06      | **Lockout file deleted:** Remove lockout file; verify rate limiting resets | New lockout file created; 5 more attempts allowed |
| TA-07      | **User removed:** Delete user's credential files; verify graceful failure | PAM_IGNORE or PAM_USER_UNKNOWN |
| TA-08      | **Forged challenge:** Client sends crafted challenge bytes | Daemon rejects (user-ctx hash mismatch) |
| TA-09      | **Socket connection from non-root:** Attempt to connect to auth.sock as non-root | Connection refused (socket is 0600 root) |
| TA-10      | **Degraded mode + PIN brute force:** Attempt all 4-digit PINs (10,000 attempts) | Software lockout activates at 5 attempts |

### G5. Platform Compatibility Tests

| Test ID    | Description                                     | Expected              |
|------------|-------------------------------------------------|-----------------------|
| TP-01      | Ubuntu 22.04 LTS, fTPM                         | All TI + TA pass      |
| TP-02      | Ubuntu 22.04 LTS, no TPM (degraded mode)       | Auth works; degraded warning shown |
| TP-03      | Fedora 39 with GDM                             | GDM login succeeds via PAM |
| TP-04      | Fedora 39 with SDDM                            | SDDM login succeeds via PAM |
| TP-05      | Console login (getty + PAM)                    | Login succeeds          |
| TP-06      | sudo (if PAM stack configured)                 | sudo uses LinuxHello    |
| TP-07      | Screen lock (gnome-screensaver)                | Unlock succeeds         |
| TP-08      | Fingerprint reader: Validity Sensors VFS5011   | Biometric path works    |
| TP-09      | Fingerprint reader absent                      | PIN-only mode, no crash |

### G6. Enrollment / Revocation Tests

| Test ID    | Description                                     | Expected              |
|------------|-------------------------------------------------|-----------------------|
| TE-01      | `lh-enroll enroll` as root → success           | Credential files created |
| TE-02      | `lh-enroll enroll` as non-root → error         | "must be root" error  |
| TE-03      | `lh-enroll enroll` duplicate → warns + aborts  | Warning, no overwrite |
| TE-04      | `lh-enroll revoke` → files removed, TPM key evicted | State clean       |
| TE-05      | `lh-enroll status` enrolled user               | Shows correct metadata |
| TE-06      | `lh-enroll status` non-enrolled user           | "No credential" message |
| TE-07      | `lh-enroll rotate` → revoke + re-enroll        | New credential works  |
| TE-08      | Enroll with PIN < 4 chars → rejected           | Error + retry prompt  |
| TE-09      | PIN mismatch on confirmation → retry           | Prompts again         |
| TE-10      | Enroll in degraded mode (`--degraded`)         | Warning shown; sw key created |

### G7. Running the Tests

```bash
# Install build dependencies (Ubuntu/Debian):
sudo apt-get install -y \
    cmake build-essential \
    libssl-dev \
    libpam0g-dev \
    libtss2-dev \           # tpm2-tss (optional)
    libglib2.0-dev \        # GLib/GIO for fprintd (optional)
    fprintd                 # for biometric tests (optional)

# Build:
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build

# Run unit tests:
ctest --test-dir build --output-on-failure

# Run individual test binaries:
./build/tests/test_crypto
./build/tests/test_challenge
./build/tests/test_storage

# Integration tests (requires root and a running daemon):
sudo ./build/lhd --foreground --debug &
sudo ./build/lh-enroll enroll --user testuser --no-biometric
# Then run the PAM integration test script (see tests/integration/)
```
