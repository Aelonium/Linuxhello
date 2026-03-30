# LinuxHello

A Linux implementation of a Windows Hello-style local authentication
system using TPM 2.0 hardware-protected credentials with biometric or PIN
unlock gestures.  **No network dependency. No AD/Entra. Strictly local.**

---

## Overview

LinuxHello replaces password-based local login/unlock with a device-bound
public-key credential:

- **Private key** lives inside the TPM 2.0 and is **non-exportable**
  (`fixedTPM | fixedParent` attributes).  It never leaves the hardware.
- **Authentication** uses challenge–response: the daemon generates a nonce,
  the TPM signs it, the signature is verified against the stored public key.
- **Biometrics / PIN** are *unlock gestures* only – they gate access to the
  TPM key locally and are never transmitted as a shared secret.
- **Biometric templates** remain inside `fprintd`/`libfprint` and are never
  exposed to LinuxHello code.
- **Rate limiting** is enforced by the TPM's built-in dictionary-attack (DA)
  lockout and a software counter backed by TPM NVRAM.

---

## Security Model

```
  Enrollment:   TPM generates ECC P-256 key pair (private key stays in TPM)
                Public key stored in /var/lib/linuxhello/<user>/pubkey.der
                Biometric template enrolled in fprintd (separate store)

  Authentication:
    1. Daemon generates 72-byte challenge (nonce + timestamp + user-ctx)
    2. Biometric/PIN gesture gates the TPM signing operation
    3. TPM signs the challenge (ECDSA-P256-SHA256)
    4. Daemon verifies signature against stored public key
    5. PAM_SUCCESS if valid, PAM_AUTH_ERR otherwise
```

See [`docs/architecture.md`](docs/architecture.md) for full design details.

---

## Directory Structure

```
LinuxHello/
├── CMakeLists.txt              Build system
├── docs/
│   ├── architecture.md         Full architecture + cryptographic design
│   ├── security-analysis.md    Attack/mitigation table + hardening guide
│   └── test-plan.md            Unit, integration, and threat test plan
├── pam.d/
│   └── linuxhello              PAM configuration snippet
├── src/
│   ├── common/
│   │   └── linuxhello.h        Shared types, constants, IPC protocol
│   ├── crypto/
│   │   ├── challenge.c/.h      Challenge generation and validation
│   │   ├── tpm_ops.c/.h        TPM 2.0 ESAPI key operations
│   │   └── tpm_ops_stub.c      Stub for builds without tpm2-tss
│   ├── biometric/
│   │   └── fprintd_client.c/.h fprintd D-Bus biometric client
│   ├── storage/
│   │   └── storage.c/.h        Credential + lockout state persistence
│   ├── pam/
│   │   └── pam_linuxhello.c    PAM module (auth + account hooks)
│   ├── daemon/
│   │   └── lhd.c/.h            Auth broker daemon
│   └── enroll/
│       └── lh-enroll.c         Enrollment / revocation / status CLI
├── systemd/
│   └── linuxhello.service      systemd service unit
└── tests/
    ├── CMakeLists.txt
    ├── test_crypto.c           Crypto + signature unit tests
    ├── test_challenge.c        Challenge protocol unit tests
    └── test_storage.c          Storage + lockout unit tests
```

---

## Building

### Dependencies

| Package             | Required | Purpose                        |
|---------------------|----------|--------------------------------|
| `libssl-dev`        | Yes      | ECC key ops, ECDSA, PBKDF2     |
| `libpam0g-dev`      | Yes      | PAM module                     |
| `libtss2-dev`       | No*      | TPM 2.0 ESAPI (tpm2-tss)       |
| `libglib2.0-dev`    | No*      | fprintd D-Bus client (GLib)    |
| `fprintd`           | No*      | Biometric daemon               |
| `tpm2-abrmd`        | No*      | TPM resource manager           |

*Optional: LinuxHello builds and runs in degraded mode without these.

### Build steps

```bash
# Install minimum dependencies (Ubuntu/Debian):
sudo apt-get install -y cmake build-essential libssl-dev libpam0g-dev

# Optional: full TPM + biometric support:
sudo apt-get install -y libtss2-dev libglib2.0-dev fprintd tpm2-abrmd

# Configure and build:
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Run unit tests:
ctest --test-dir build --output-on-failure

# Install (requires root):
sudo cmake --install build
sudo systemctl enable --now linuxhello
```

---

## Enrollment

```bash
# Enroll the current user (must run as root):
sudo lh-enroll enroll

# Enroll another user:
sudo lh-enroll enroll --user alice

# Check status:
sudo lh-enroll status --user alice

# Revoke credential (removes TPM key + biometric + files):
sudo lh-enroll revoke --user alice

# Rotate (revoke + re-enroll atomically):
sudo lh-enroll rotate --user alice
```

---

## PAM Configuration

Add to `/etc/pam.d/common-auth` (Debian/Ubuntu) or equivalent:

```
# LinuxHello with password fallback (recommended for initial rollout):
auth  [success=1 new_authtok_reqd=ok ignore=ignore default=ignore] \
            pam_linuxhello.so

# Existing password auth (fallback):
auth  [success=1 default=die]  pam_unix.so nullok_secure try_first_pass
```

For screen unlock with GDM, add to `/etc/pam.d/gdm-password`:
```
auth  sufficient  pam_linuxhello.so
@include common-auth
```

---

## Degraded Mode (no TPM)

If no TPM 2.0 is present, LinuxHello falls back to a software-protected
key encrypted with AES-256-GCM derived from the PIN via PBKDF2 (210,000
iterations).

⚠️ **Degraded mode is explicitly NOT equivalent to TPM mode.**
A root attacker with disk access can attempt to brute-force the PIN.
Hardware lockout is unavailable.  Users are warned during enrollment.

---

## Threat Model

See [`docs/security-analysis.md`](docs/security-analysis.md) for the
full attack/mitigation table and hardening recommendations (Secure Boot,
PCR sealing, disk encryption integration, IMA).

**LinuxHello defends against:**
- Physical theft (no password hash to crack; need TPM + PIN/biometric)
- Remote attackers (no reusable secret transmitted or stored)
- Replay attacks (nonce + 30s window + user-host binding)
- PIN brute-force (TPM DA lockout + software counter)

**Acknowledged limitations:**
- Root-level OS compromise can intercept the PIN on the Unix socket
- No Virtualization-Based Security (VBS) equivalent
- Kernel-level malware can bypass all userspace protections
- Discrete TPM bus sniffing is possible (mitigated by fTPM)

---

## License

MIT License – see `LICENSE` file.
