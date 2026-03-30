/*
 * ir_face.h – IR camera face recognition for LinuxHello
 *
 * Replaces the fprintd fingerprint backend with a local IR face
 * recognition pipeline running entirely in-process via OpenCV.
 *
 * Hardware:
 *   Uses the IR (near-infrared) camera exposed as /dev/video2 on this
 *   system (0c45:6a0f Microdia Integrated_Webcam_HD, GREY pixel format).
 *   IR illumination makes the pipeline inherently resistant to spoofing
 *   with printed photographs and screens.
 *
 * Pipeline:
 *   1. V4L2 capture via OpenCV VideoCapture, GREY format
 *   2. Face detection – Haar cascade (bundled with OpenCV)
 *   3. Liveness check – Laplacian variance of IR face crop
 *   4. Feature extraction – 64-cell uniform-LBP histogram (3776 floats)
 *      IL-normalised per cell, L2-normalised overall; well-suited to
 *      monochrome IR illumination.
 *   5. Template storage – AES-256-GCM encrypted, key derived from the
 *      user's TPM public key DER + username.  Revoking the TPM key
 *      also invalidates the face template.
 *
 * Security model:
 *   Biometric result is an "unlock gesture" – it authorises a subsequent
 *   TPM signing operation but is NOT itself the secret.  Even if the face
 *   template were extracted from disk (it is AES-encrypted), the adversary
 *   still cannot forge a valid TPM signature without the private key
 *   inside the TPM.
 */

#ifndef IR_FACE_H
#define IR_FACE_H

#include <stdint.h>
#include <stddef.h>
#include "../common/linuxhello.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Configuration ────────────────────────────────────────── */

/** V4L2 device index for the IR camera (/dev/video2) */
#define LH_IR_DEVICE_IDX  2
/** V4L2 device path for error messages / diagnostics */
#define LH_IR_DEVICE      "/dev/video2"
/** Haar cascade shipped with libopencv-objdetect-dev */
#define LH_FACE_CASCADE   "/usr/share/opencv4/haarcascades/haarcascade_frontalface_default.xml"
/** Seconds to wait for a face during verification */
#define LH_FACE_TIMEOUT_S 20

/** AES-256-GCM encrypted face embedding file */
#define LH_FACE_EMB_FILE_FMT  LH_STATE_DIR "/%s/face_embedding.enc"

/* ── Result codes ─────────────────────────────────────────── */

/** Shared with the daemon's lh_bio_result_t convention */
typedef enum lh_bio_result {
    LH_BIO_OK          = 0,   /* face matched enrolled template        */
    LH_BIO_NOMATCH     = 1,   /* face detected but didn't match        */
    LH_BIO_TIMEOUT     = 2,   /* no face placed in camera within limit */
    LH_BIO_ERROR       = 3,   /* camera / cascade / crypto error       */
    LH_BIO_NOTENROLLED = 4,   /* no face template enrolled for user    */
} lh_bio_result_t;

/** lh_face_enroll return codes */
typedef enum lh_face_enroll_rc {
    LH_FACE_OK           =  0,   /* success                             */
    LH_FACE_ERR_DEVICE   = -1,   /* cannot open IR camera               */
    LH_FACE_ERR_TIMEOUT  = -2,   /* ran out of time before enough frames*/
    LH_FACE_ERR_CRYPTO   = -3,   /* encryption / file-write failed      */
    LH_FACE_ERR_CASCADE  = -4,   /* Haar cascade not found              */
    LH_FACE_ERR_NO_FRAME = -5,   /* camera opened but produced no frames*/
} lh_face_enroll_rc_t;

/* ── Public API ───────────────────────────────────────────── */

/**
 * lh_ir_camera_test – Verify that the IR camera is present and functional.
 *
 * Opens the V4L2 device, attempts to capture up to 10 frames, checks that
 * at least one non-empty frame is received, then closes the device.
 * Does NOT require a face to be present.
 *
 * This is called at the start of biometric enrollment to give an early,
 * clear error if the IR camera is missing or mis-configured.  If this
 * function returns non-zero, enrollment MUST be aborted rather than
 * silently falling back to PIN-only mode.
 *
 * @returns  LH_FACE_OK         (0)   camera is working
 *           LH_FACE_ERR_DEVICE (-1)  device node absent or cannot be opened
 *           LH_FACE_ERR_NO_FRAME(-5) device opened but produced no frames
 *                                    (driver issue / wrong pixel format)
 */
int lh_ir_camera_test(void);

/**
 * lh_face_enroll – Capture IR frames, build LBP face template,
 * AES-256-GCM encrypt it (key tied to @pubkey_der), save to disk.
 *
 * Blocks until ENROLL_FRAMES good samples are collected or timeout.
 * Must be called as root (writes to LH_STATE_DIR).
 *
 * @param username       Local user name (directory must already exist)
 * @param pubkey_der     User's TPM public key DER – used to derive
 *                       the template encryption key
 * @param pubkey_der_len Length of pubkey_der in bytes
 * @returns lh_face_enroll_rc_t (0 = success)
 */
int lh_face_enroll(const char    *username,
                   const uint8_t *pubkey_der,
                   size_t         pubkey_der_len);

/**
 * lh_face_verify – Capture IR frames, compare against stored template.
 *
 * Opens the IR camera, waits up to LH_FACE_TIMEOUT_S seconds for a
 * matching face.  Used by the daemon in each forked auth child.
 *
 * @param username        Local user name
 * @param pubkey_der      User's TPM public key DER (for key derivation)
 * @param pubkey_der_len  Length in bytes
 * @returns lh_bio_result_t
 */
lh_bio_result_t lh_face_verify(const char    *username,
                                const uint8_t *pubkey_der,
                                size_t         pubkey_der_len);

/**
 * lh_face_is_enrolled – Returns 1 if a face template is present on disk,
 * 0 otherwise (does not validate the encrypted content).
 */
int lh_face_is_enrolled(const char *username);

/**
 * lh_face_delete – Remove the face embedding file for @username.
 * Returns 0 on success or if not present.
 */
int lh_face_delete(const char *username);

#ifdef __cplusplus
}
#endif

#endif /* IR_FACE_H */
