/*
 * fprintd_client.h – fprintd D-Bus client for biometric verification
 *
 * LinuxHello uses fprintd (the freedesktop fingerprint daemon) to
 * perform biometric verification.  Biometrics serve exclusively as a
 * "local unlock gesture" that gates access to the TPM key.
 *
 * Security note:
 *   Biometric template data is NEVER handled here; it remains inside
 *   fprintd / libfprint.  This module only asks fprintd "is the user
 *   who they claim to be?" and acts on the boolean answer.
 *   The biometric result does NOT become a secret or credential –
 *   it merely authorises a subsequent TPM signing operation.
 *
 * Liveness limitation:
 *   libfprint does not currently provide verified liveness detection
 *   for most hardware.  The security model treats biometrics as a
 *   convenience factor; the private key in the TPM is the actual
 *   authenticator.  Spoofed biometrics can trigger the key use but
 *   cannot exfiltrate the private key.
 */

#ifndef FPRINTD_CLIENT_H
#define FPRINTD_CLIENT_H

#include <stdbool.h>
#include "../common/linuxhello.h"

/* Timeout waiting for a fingerprint scan (seconds) */
#define LH_BIOMETRIC_TIMEOUT_S  30

typedef enum lh_bio_result {
    LH_BIO_OK      = 0,   /* fingerprint matched enrolled template */
    LH_BIO_NOMATCH = 1,   /* fingerprint did not match            */
    LH_BIO_TIMEOUT = 2,   /* no finger placed within timeout      */
    LH_BIO_ERROR   = 3,   /* fprintd unavailable or internal error */
    LH_BIO_NOTENROLLED = 4, /* user has no enrolled finger         */
} lh_bio_result_t;

/**
 * lh_bio_verify – Ask fprintd to verify the fingerprint for @username.
 *
 * This call blocks (up to LH_BIOMETRIC_TIMEOUT_S seconds) waiting for
 * the user to place a finger.  If fprintd is not running or the user
 * has no enrolled fingerprint, returns LH_BIO_ERROR / LH_BIO_NOTENROLLED.
 *
 * @param username   Local user to verify
 * @returns lh_bio_result_t
 */
lh_bio_result_t lh_bio_verify(const char *username);

/**
 * lh_bio_enroll – Start an enrollment session for @username via fprintd.
 *
 * This call is interactive: fprintd will prompt the user to swipe the
 * finger multiple times.  It blocks until enrollment completes or fails.
 *
 * @param username   Local user to enroll
 * @returns 0 on success, -1 on failure
 */
int lh_bio_enroll(const char *username);

/**
 * lh_bio_is_enrolled – Check whether @username has at least one enrolled
 * fingerprint in fprintd.
 *
 * @returns true if enrolled, false otherwise
 */
bool lh_bio_is_enrolled(const char *username);

/**
 * lh_bio_delete_enrolled – Remove all enrolled fingerprints for @username
 * from fprintd.  Called during credential revocation.
 *
 * @returns 0 on success, -1 on failure
 */
int lh_bio_delete_enrolled(const char *username);

#endif /* FPRINTD_CLIENT_H */
