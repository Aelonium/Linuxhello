# LinuxHello – Security Analysis

## F. Attack / Mitigation Table

| Attack                              | Mitigation                                      | Residual Risk            |
|-------------------------------------|-------------------------------------------------|--------------------------|
| **Stolen device, offline attack**   | Private key in TPM (non-exportable); requires PIN or biometric to use | Root can access storage; TPM-sealed keys are inaccessible without TPM+PIN |
| **OS compromise (root)**            | TPM key is hardware-protected; root cannot export private key | Root CAN intercept PIN during PAM auth (see below); root can defeat software lockout in degraded mode |
| **Replay attack**                   | 30-second challenge window + user+host binding | None significant; window is narrow |
| **Brute-force against PIN**         | TPM DA lockout (hardware); software lockout (5 attempts / 5 min) | TPM lockout recovery possible after reboot+timeout |
| **Biometric spoofing**              | Biometric gates the challenge flow, not the key; private key still TPM-protected | Liveness detection is hardware-dependent; some readers accept latent prints |
| **Man-in-the-middle (local)**       | Unix socket is root:root 0600; PAM runs as root | A root attacker can intercept the socket |
| **Credential file tampering**       | Files are root:root 0600; daemon recomputes SHA-256 | Root can replace pubkey.der (then any key signs); mitigated by measured boot + IMA |
| **Cross-machine replay**            | User+hostname context hash in challenge | Attacker who knows the hostname can forge context (but still needs the TPM key) |
| **Degraded-mode offline brute force** | AES-256-GCM + PBKDF2 (210K iterations); software lockout | Root attacker with disk access can attempt offline PIN crack; hardware lockout unavailable |
| **Kernel-level attacker**           | Kernel can intercept TPM bus; defence requires measured boot | Not mitigated without measured/secure boot |
| **Physical TPM extraction**         | TPM key policy requires PIN; without PIN the key cannot be used | PIN brute force against the chip is still possible (TPM DA mitigates) |
| **TPM bus sniffing (discrete TPM)** | PIN is sent only to the TPM as authValue; still visible on LPC/SPI bus | Discrete TPM chips (LPC/SPI) are vulnerable; fTPM (firmware TPM) is not |

---

## What Remains Vulnerable vs Windows Hello

| Property                            | Windows Hello           | LinuxHello (TPM mode)    |
|-------------------------------------|-------------------------|--------------------------|
| Kernel trust boundary               | Hypervisor-Protected Code Integrity (HVCI) possible | No equivalent; kernel compromise breaks all bets |
| Anti-cheat / measured boot baseline | Secure Boot + VBS       | Secure Boot (UEFI); no VBS |
| Credential guard                    | Credential Guard in VSM | No VSM; credentials are in the OS |
| Root-level attack                   | Mitigated with HVCI/VBS | Root can intercept PIN on socket |
| Biometric template protection       | Stored in VSM           | Stored in fprintd (root-accessible) |
| Cross-device credential sharing     | Not possible (TPM bound)| Not possible (TPM bound) |
| Firmware TPM (fTPM) security        | Supported               | Supported (same behaviour) |
| Discrete TPM bus sniffing           | Same risk               | Same risk                |

The key difference is that Linux has no equivalent of Windows' Virtualization-Based Security (VBS) or Hypervisor-Protected Code Integrity (HVCI).  A root compromise on Linux gives access to everything in the OS, including the PAM conversation and the Unix socket to lhd.  On Windows, VSM creates an isolated region the OS cannot read.

**Practical implication:** LinuxHello provides strong security against:
- Physical theft (disk encryption + TPM key + PIN)
- Non-root attackers
- Network attackers (no password hash to steal remotely)

It provides *weaker* guarantees than Windows Hello against a root-level attacker.

---

## G. Hardening Recommendations

### 1. Measured Boot / Secure Boot

Enable UEFI Secure Boot.  This ensures that the bootloader and kernel
are signed by the platform key, preventing an attacker from booting a
modified kernel that bypasses LinuxHello.

```bash
# Verify Secure Boot is active
mokutil --sb-state
# Expected: SecureBoot enabled
```

### 2. Sealing Keys to PCRs

For the highest security, the TPM key's policy should additionally bind
to PCR values that reflect the current boot state:

```c
// During enrollment: add PCR policy
Esys_PolicyPCR(ctx, policy_session, NULL, &pcr_digest, &pcr_selection);
// This seals the key to the current measured boot state.
// If PCR 7 (Secure Boot state) changes, the key policy fails.
```

Suggested PCRs:
| PCR | Content                        | Why bind?                     |
|-----|--------------------------------|-------------------------------|
| 0   | UEFI firmware                  | Detects firmware tampering     |
| 4   | Boot loader                    | Detects bootloader replacement |
| 7   | Secure Boot state / variables  | Detects Secure Boot bypass     |

**Trade-off:** PCR binding means the key becomes unusable after legitimate
firmware updates; re-enrollment required.

### 3. Disk Encryption Integration

Use LUKS2 + `systemd-cryptenroll` to bind disk encryption to the same TPM:

```bash
systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+4+7 /dev/sda3
```

This ensures that the encrypted disk cannot be read without the correct
boot state.  Combined with LinuxHello, an attacker who steals the disk
cannot decrypt it, and even if they boot the correct kernel, they need
the PIN to use the LinuxHello credential.

### 4. Biometric Template Isolation

Currently biometric templates are managed by fprintd running as root.
For stronger isolation:

- Run fprintd with a dedicated service account and tight seccomp/apparmor profile
- Use AppArmor or SELinux to prevent other processes from reading fprintd's
  template storage (`/var/lib/fprint/`)
- Consider kernel keyring or TPM-sealed storage for template encryption keys

```
# Example AppArmor profile fragment for fprintd
/usr/libexec/fprintd {
    /var/lib/fprint/** rw,
    deny /proc/** rwklx,
    ...
}
```

### 5. IMA (Integrity Measurement Architecture)

Enable IMA to detect tampering with credential files:

```bash
# /etc/ima/ima-policy
appraise func=FILE_CHECK fowner=0 mask=MAY_READ label=security.ima
```

This ensures that if `pubkey.der` is replaced by an attacker, the IMA
appraisal will fail and the system will refuse to use the tampered file.

### 6. Unix Socket Access Control

While the socket is already root:root 0600, additional hardening:

- Use systemd socket activation with `SocketUser=root SocketGroup=_linuxhello`
- Add PAM module group to control which processes can open the socket
- Consider switching to a systemd-managed `AF_VSOCK` for future VM scenarios

---

## H. Threat Model Summary

### In scope (LinuxHello defends against these)

1. **Stolen device, disk readable:** No password hash to crack; need TPM + PIN
2. **Remote attacker:** No password hash transmitted or stored (no phishing)
3. **Replay of captured session token:** Challenge-response prevents replay
4. **Brute-force of PIN:** TPM DA lockout + software lockout limit attempts
5. **Non-root local attacker:** Files and socket are root-only

### Out of scope (acknowledged limitations)

1. **Root-level attacker on a running system:** Can intercept PIN on socket
2. **Kernel-level malware:** Can bypass all userspace protections
3. **Firmware-level attack (e.g., UEFI rootkit):** Requires measured boot + TPM PCR sealing
4. **Physical TPM bus sniffing (discrete TPM):** Applies to all TPM-based systems
5. **Biometric liveness detection:** Hardware-dependent; not guaranteed
6. **Degraded mode PIN brute-force by root:** Software-only, no hardware backstop
