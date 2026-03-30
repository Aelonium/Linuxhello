/*
 * ir_face.cpp – IR camera face recognition for LinuxHello
 *
 * See ir_face.h for architecture overview.
 *
 * LBP embedding details
 * ─────────────────────
 * Each face is normalised to 128×128, histogram-equalised, then divided
 * into an 8×8 grid of 16×16-pixel cells.  Each cell gets a 59-bin
 * uniform-LBP histogram (58 circular-uniform patterns + 1 catch-all),
 * L1-normalised.  The 64 histograms are concatenated and L2-normalised
 * to produce a 3776-dimensional unit-length feature vector.
 *
 * Comparison uses chi-squared distance (lower = more similar).  The
 * threshold 0.35 was experimentally chosen to give a low FAR while
 * tolerating moderate illumination changes from the IR emitters.
 *
 * Encryption format
 * ─────────────────
 *   face_embedding.enc  =  IV(12) || AES-256-GCM(plaintext) || GCM-tag(16)
 *
 *   key = SHA-256(pubkey_der || "\x00linuxhello_face_v1\x00" || username)
 *
 * Linking remark
 * ──────────────
 * This file is C++ (to use the OpenCV API).  All exported symbols are
 * declared inside  extern "C"  so the daemon and enrollment tool (both C)
 * can link against them without name-mangling issues.
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <vector>
#include <chrono>
#include <algorithm>

#include <sys/stat.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include <opencv2/core.hpp>
#include <opencv2/imgproc.hpp>
#include <opencv2/objdetect.hpp>
#include <opencv2/videoio.hpp>

#include "ir_face.h"

/* ═══════════════════════════════════════════════════════════
 * Internal constants
 * ═══════════════════════════════════════════════════════════ */

static constexpr int FACE_W        = 128;   /* normalised face width   */
static constexpr int FACE_H        = 128;   /* normalised face height  */
static constexpr int LBP_GRID_X    = 8;     /* histogram grid columns  */
static constexpr int LBP_GRID_Y    = 8;     /* histogram grid rows     */
static constexpr int LBP_BINS      = 59;    /* uniform LBP bins        */
static constexpr int FEAT_DIM      = LBP_GRID_X * LBP_GRID_Y * LBP_BINS; /* 3776 */
static constexpr int MIN_FACE_PX   = 60;    /* min detection size      */
static constexpr double LAP_MIN    = 30.0;  /* liveness: Laplacian var */
static constexpr double CHI2_THRESH= 0.35;  /* match threshold         */
static constexpr int ENROLL_FRAMES = 20;    /* good frames to average  */
static constexpr int ENROLL_TIMEOUT= 30;    /* seconds                 */
static constexpr int GCM_IV_LEN    = 12;
static constexpr int GCM_TAG_LEN   = 16;

/* ════════════════════════════════════════════════════════════
 * LBP helpers
 * ════════════════════════════════════════════════════════════ */

/*
 * build_uniform_table – precompute mapping from 8-bit LBP code → bin index.
 *
 * Uniform LBP: code has at most 2 bitwise 0→1 or 1→0 transitions when
 * read circularly.  There are 58 such patterns (bins 0–57); all others
 * map to bin 58 (non-uniform catch-all).
 */
static const int *get_uniform_table()
{
    static int table[256];
    static bool ready = false;
    if (ready) return table;

    int bin = 0;
    for (int i = 0; i < 256; ++i) {
        /* Count circular 01/10 transitions */
        int b    = i;
        int prev = (b >> 7) & 1;
        int trans = 0;
        for (int bit = 0; bit < 8; ++bit) {
            int cur = (b >> bit) & 1;
            if (cur != prev) ++trans;
            prev = cur;
        }
        table[i] = (trans <= 2) ? bin++ : 58;
    }
    ready = true;
    return table;
}

/*
 * cell_lbp_hist – compute 59-bin uniform-LBP histogram for a grayscale
 * image patch, L1-normalised.
 */
static std::vector<float> cell_lbp_hist(const cv::Mat &patch)
{
    const int *lut = get_uniform_table();
    std::vector<float> hist(LBP_BINS, 0.0f);
    const int R = patch.rows, C = patch.cols;

    for (int y = 1; y < R - 1; ++y) {
        const uint8_t *row = patch.ptr<uint8_t>(y);
        for (int x = 1; x < C - 1; ++x) {
            uint8_t c = row[x];
            uint8_t code = 0;
            /* 8 neighbours, clockwise from top-left */
            code |= (uint8_t)(patch.at<uint8_t>(y-1,x-1) >= c) << 7;
            code |= (uint8_t)(patch.at<uint8_t>(y-1,x  ) >= c) << 6;
            code |= (uint8_t)(patch.at<uint8_t>(y-1,x+1) >= c) << 5;
            code |= (uint8_t)(patch.at<uint8_t>(y  ,x+1) >= c) << 4;
            code |= (uint8_t)(patch.at<uint8_t>(y+1,x+1) >= c) << 3;
            code |= (uint8_t)(patch.at<uint8_t>(y+1,x  ) >= c) << 2;
            code |= (uint8_t)(patch.at<uint8_t>(y+1,x-1) >= c) << 1;
            code |= (uint8_t)(patch.at<uint8_t>(y  ,x-1) >= c) << 0;
            hist[lut[code]] += 1.0f;
        }
    }
    /* L1 normalise */
    float sum = 0.0f;
    for (float v : hist) sum += v;
    if (sum > 0.0f) for (float &v : hist) v /= sum;
    return hist;
}

/*
 * face_to_feature – extract the 3776-dim feature vector from a 128×128
 * grayscale face image.  Returns an L2-normalised vector.
 */
static std::vector<float> face_to_feature(const cv::Mat &face)
{
    cv::Mat eq;
    cv::equalizeHist(face, eq);   /* histogram equalisation for IR variance */

    std::vector<float> feat;
    feat.reserve(FEAT_DIM);

    const int cw = FACE_W / LBP_GRID_X;  /* 16 */
    const int ch = FACE_H / LBP_GRID_Y;  /* 16 */

    for (int gy = 0; gy < LBP_GRID_Y; ++gy) {
        for (int gx = 0; gx < LBP_GRID_X; ++gx) {
            cv::Mat cell = eq(cv::Rect(gx*cw, gy*ch, cw, ch));
            auto h = cell_lbp_hist(cell);
            feat.insert(feat.end(), h.begin(), h.end());
        }
    }

    /* L2 normalise */
    float norm = 0.0f;
    for (float v : feat) norm += v * v;
    norm = std::sqrt(norm);
    if (norm > 1e-6f) for (float &v : feat) v /= norm;
    return feat;
}

/* ════════════════════════════════════════════════════════════
 * Liveness check
 * ════════════════════════════════════════════════════════════ */

/*
 * Laplacian variance: measures high-frequency content in the IR image.
 * A real face at typical distance has variance driven by skin texture,
 * nose/eye shadows, and eyelashes.  A flat printed photo or screen has
 * distinctly different (often lower) variance characteristics.
 */
static double laplacian_variance(const cv::Mat &gray)
{
    cv::Mat lap;
    cv::Laplacian(gray, lap, CV_64F);
    cv::Scalar mean, stddev;
    cv::meanStdDev(lap, mean, stddev);
    return stddev[0] * stddev[0];
}

static bool liveness_ok(const cv::Mat &face_crop)
{
    return laplacian_variance(face_crop) >= LAP_MIN;
}

/* ════════════════════════════════════════════════════════════
 * Chi-squared distance
 * ════════════════════════════════════════════════════════════ */

static double chi2(const std::vector<float> &a, const std::vector<float> &b)
{
    double d = 0.0;
    for (size_t i = 0; i < a.size(); ++i) {
        double diff  = a[i] - b[i];
        double denom = a[i] + b[i] + 1e-7;
        d += (diff * diff) / denom;
    }
    return d;
}

/* ════════════════════════════════════════════════════════════
 * Face detection
 * ════════════════════════════════════════════════════════════ */

static cv::CascadeClassifier &get_cascade()
{
    static cv::CascadeClassifier cascade;
    static bool loaded = false;
    if (!loaded) {
        loaded = cascade.load(LH_FACE_CASCADE);
        if (!loaded)
            fprintf(stderr,
                    "[linuxhello/face] Haar cascade not found at: %s\n",
                    LH_FACE_CASCADE);
    }
    return cascade;
}

struct FaceFrame {
    cv::Mat face;      /* 128×128 greyscale normalised face */
    double  lap_var;   /* liveness score                    */
};

/* Returns true if a face was detected; fills out. */
static bool detect_face(const cv::Mat &frame, FaceFrame &out)
{
    cv::CascadeClassifier &cascade = get_cascade();
    if (cascade.empty()) return false;

    std::vector<cv::Rect> faces;
    cascade.detectMultiScale(frame, faces,
                             1.1,   /* scale factor                  */
                             5,     /* minNeighbours – reduce jitter  */
                             0,
                             cv::Size(MIN_FACE_PX, MIN_FACE_PX));
    if (faces.empty()) return false;

    /* Pick the largest detected face */
    const cv::Rect &best = *std::max_element(
        faces.begin(), faces.end(),
        [](const cv::Rect &a, const cv::Rect &b){ return a.area() < b.area(); });

    cv::Rect clipped = best & cv::Rect(0, 0, frame.cols, frame.rows);
    if (clipped.area() < MIN_FACE_PX * MIN_FACE_PX) return false;

    cv::Mat crop = frame(clipped);
    out.lap_var  = laplacian_variance(crop);
    cv::resize(crop, out.face, cv::Size(FACE_W, FACE_H), 0, 0, cv::INTER_LINEAR);
    return true;
}

/* ════════════════════════════════════════════════════════════
 * Encryption / decryption
 * ════════════════════════════════════════════════════════════ */

/*
 * derive_face_key – deterministic AES-256 key from the user's TPM pubkey.
 *
 * key = SHA-256(pubkey_der || "\x00linuxhello_face_v1\x00" || username)
 *
 * Consequence: revoking the TPM credential (which changes or deletes
 * pubkey.der) also invalidates the face template.
 */
static void derive_face_key(const uint8_t *pub, size_t pub_len,
                             const char *username, uint8_t out[32])
{
    static const char INFO[] = "\x00linuxhello_face_v1\x00";
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, pub, pub_len);
    SHA256_Update(&ctx, INFO, sizeof(INFO)); /* includes trailing NUL */
    SHA256_Update(&ctx, username, strlen(username));
    SHA256_Final(out, &ctx);
}

static int encrypt_embedding(const std::vector<float> &feat,
                              const uint8_t *pub, size_t pub_len,
                              const char *username, const char *path)
{
    uint8_t key[32], iv[GCM_IV_LEN], tag[GCM_TAG_LEN];
    derive_face_key(pub, pub_len, username, key);
    if (RAND_bytes(iv, GCM_IV_LEN) != 1) { memset(key,0,32); return -1; }

    const size_t pt_len = feat.size() * sizeof(float);
    std::vector<uint8_t> ct(pt_len);

    EVP_CIPHER_CTX *ectx = EVP_CIPHER_CTX_new();
    int rc = -1;
    if (ectx) {
        int n = 0;
        if (EVP_EncryptInit_ex(ectx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
            EVP_EncryptInit_ex(ectx, NULL, NULL, key, iv) &&
            EVP_EncryptUpdate(ectx, ct.data(), &n,
                              reinterpret_cast<const uint8_t*>(feat.data()),
                              (int)pt_len) &&
            EVP_EncryptFinal_ex(ectx, ct.data()+n, &n) &&
            EVP_CIPHER_CTX_ctrl(ectx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag))
            rc = 0;
        EVP_CIPHER_CTX_free(ectx);
    }
    memset(key, 0, 32);
    if (rc != 0) return -1;

    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    bool ok = (fwrite(iv,       1, GCM_IV_LEN,  f) == (size_t)GCM_IV_LEN)  &&
              (fwrite(ct.data(),1, ct.size(),    f) == ct.size())            &&
              (fwrite(tag,      1, GCM_TAG_LEN,  f) == (size_t)GCM_TAG_LEN);
    fclose(f);
    if (ok) chmod(path, 0600);
    return ok ? 0 : -1;
}

static int decrypt_embedding(const char *path,
                              const uint8_t *pub, size_t pub_len,
                              const char *username,
                              std::vector<float> &out)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fseek(f, 0, SEEK_SET);

    const long expected = GCM_IV_LEN + (long)(FEAT_DIM * sizeof(float)) + GCM_TAG_LEN;
    if (fsz != expected) { fclose(f); return -1; }

    std::vector<uint8_t> buf((size_t)fsz);
    if ((long)fread(buf.data(), 1, (size_t)fsz, f) != fsz) { fclose(f); return -1; }
    fclose(f);

    uint8_t key[32];
    derive_face_key(pub, pub_len, username, key);

    const uint8_t *iv  = buf.data();
    const uint8_t *ct  = buf.data() + GCM_IV_LEN;
    const size_t pt_len = FEAT_DIM * sizeof(float);
    const uint8_t *tag = buf.data() + fsz - GCM_TAG_LEN;

    std::vector<float> pt(FEAT_DIM);
    EVP_CIPHER_CTX *dctx = EVP_CIPHER_CTX_new();
    int rc = -1;
    if (dctx) {
        int n = 0;
        if (EVP_DecryptInit_ex(dctx, EVP_aes_256_gcm(), NULL, NULL, NULL) &&
            EVP_DecryptInit_ex(dctx, NULL, NULL, key, iv)                  &&
            EVP_DecryptUpdate(dctx, reinterpret_cast<uint8_t*>(pt.data()),
                              &n, ct, (int)pt_len)                         &&
            EVP_CIPHER_CTX_ctrl(dctx, EVP_CTRL_GCM_SET_TAG, GCM_TAG_LEN,
                                const_cast<uint8_t*>(tag))                 &&
            EVP_DecryptFinal_ex(dctx,
                                reinterpret_cast<uint8_t*>(pt.data())+n,
                                &n))
            rc = 0;
        EVP_CIPHER_CTX_free(dctx);
    }
    memset(key, 0, 32);
    if (rc != 0) return -1;

    out = std::move(pt);
    return 0;
}

/* ════════════════════════════════════════════════════════════
 * Camera helper
 * ════════════════════════════════════════════════════════════ */

/*
 * try_open_device – attempt to open a specific V4L2 device path for
 * IR (greyscale) capture.  Returns true if the device opens successfully
 * and we can set the GREY pixel format.
 */
static bool try_open_device(cv::VideoCapture &cap, const char *dev_path)
{
    if (access(dev_path, F_OK) != 0) return false;
    if (!cap.open(dev_path, cv::CAP_V4L2)) return false;
    /* Request IR (greyscale) format and known resolution */
    cap.set(cv::CAP_PROP_FOURCC,
            cv::VideoWriter::fourcc('G','R','E','Y'));
    cap.set(cv::CAP_PROP_FRAME_WIDTH,  640);
    cap.set(cv::CAP_PROP_FRAME_HEIGHT, 360);
    return true;
}

/*
 * open_ir_camera – open the IR camera with auto-detection.
 *
 * Strategy:
 *   1. Try the default device (LH_IR_DEVICE, typically /dev/video2) first
 *      for backward compatibility.
 *   2. If that fails, scan /dev/video0 through /dev/video<LH_IR_DEVICE_MAX>
 *      and try each one.  For each device that opens, attempt to read a
 *      single frame and check that it is greyscale (1 channel) – a strong
 *      indicator of an IR camera rather than an RGB webcam.
 *   3. Use the first device that produces a greyscale frame.
 *
 * This auto-detection allows LinuxHello to find the IR camera regardless
 * of which /dev/video* node the kernel assigned it to.
 */
static bool open_ir_camera(cv::VideoCapture &cap)
{
    /* 1. Try the configured default device first */
    if (try_open_device(cap, LH_IR_DEVICE)) {
        /* Quick check: read one frame to see if it's greyscale */
        cv::Mat test;
        if (cap.read(test) && !test.empty() && test.channels() == 1)
            return true;
        /* Device opened but is not greyscale; close and continue scanning */
        cap.release();
    }

    /* 2. Scan /dev/video0 .. /dev/video<max> */
    for (int i = 0; i <= LH_IR_DEVICE_MAX; ++i) {
        char dev_path[32];
        snprintf(dev_path, sizeof(dev_path), "/dev/video%d", i);

        /* Skip the default device – already tried above */
        if (strcmp(dev_path, LH_IR_DEVICE) == 0) continue;

        if (!try_open_device(cap, dev_path)) continue;

        /* Check for greyscale frames (IR camera indicator) */
        cv::Mat test;
        if (cap.read(test) && !test.empty() && test.channels() == 1) {
            fprintf(stderr,
                    "[linuxhello/face] Auto-detected IR camera at %s\n",
                    dev_path);
            return true;
        }
        cap.release();
    }

    /*
     * 3. Fallback: try the default device again without the greyscale
     *    check.  Some IR cameras deliver BGR frames that we convert to
     *    grey later in the pipeline.
     */
    if (try_open_device(cap, LH_IR_DEVICE))
        return true;

    /* 4. Last resort: try any device that opens at all */
    for (int i = 0; i <= LH_IR_DEVICE_MAX; ++i) {
        char dev_path[32];
        snprintf(dev_path, sizeof(dev_path), "/dev/video%d", i);
        if (try_open_device(cap, dev_path)) {
            fprintf(stderr,
                    "[linuxhello/face] Using fallback camera at %s "
                    "(not confirmed greyscale)\n", dev_path);
            return true;
        }
    }

    return false;
}

/* Convert captured frame to single-channel greyscale regardless of
 * what VideoCapture actually decoded (GREY stays 1-ch; BGR gets converted) */
static cv::Mat to_gray(const cv::Mat &frame)
{
    if (frame.channels() == 1) return frame;
    cv::Mat g;
    cv::cvtColor(frame, g, cv::COLOR_BGR2GRAY);
    return g;
}

/* ════════════════════════════════════════════════════════════
 * Public extern "C" API
 * ════════════════════════════════════════════════════════════ */

extern "C" {

/* ── lh_face_is_enrolled ─────────────────────────────────── */
int lh_face_is_enrolled(const char *username)
{
    char path[512];
    snprintf(path, sizeof(path), LH_FACE_EMB_FILE_FMT, username);
    struct stat st;
    return (stat(path, &st) == 0) ? 1 : 0;
}

/* ── lh_face_delete ──────────────────────────────────────── */
int lh_face_delete(const char *username)
{
    char path[512];
    snprintf(path, sizeof(path), LH_FACE_EMB_FILE_FMT, username);
    if (unlink(path) != 0 && errno != ENOENT) return -1;
    return 0;
}

/* ── lh_face_enroll ──────────────────────────────────────── */
int lh_face_enroll(const char    *username,
                   const uint8_t *pubkey_der,
                   size_t         pubkey_der_len)
{
    if (get_cascade().empty()) return LH_FACE_ERR_CASCADE;

    printf("  [IR Face] Opening IR camera (%s)...\n", LH_IR_DEVICE);
    cv::VideoCapture cap;
    if (!open_ir_camera(cap)) {
        fprintf(stderr, "[linuxhello/face] Cannot open %s\n", LH_IR_DEVICE);
        return LH_FACE_ERR_DEVICE;
    }

    printf("  [IR Face] Look straight at the camera and stay still.\n");
    printf("  [IR Face] Need %d good IR frames (timeout %ds)...\n",
           ENROLL_FRAMES, ENROLL_TIMEOUT);

    std::vector<std::vector<float>> samples;
    samples.reserve(ENROLL_FRAMES);

    using Clock = std::chrono::steady_clock;
    auto deadline = Clock::now() + std::chrono::seconds(ENROLL_TIMEOUT);
    int tried = 0, rejected_liveness = 0, no_face = 0;

    while ((int)samples.size() < ENROLL_FRAMES) {
        if (Clock::now() > deadline) {
            fprintf(stderr,
                    "\n[linuxhello/face] Enrollment timed out "
                    "(%d/%d good frames collected, %d liveness fail, "
                    "%d no-face)\n",
                    (int)samples.size(), ENROLL_FRAMES,
                    rejected_liveness, no_face);
            return LH_FACE_ERR_TIMEOUT;
        }

        cv::Mat raw;
        if (!cap.read(raw) || raw.empty()) continue;
        ++tried;

        cv::Mat gray = to_gray(raw);
        FaceFrame ff;
        if (!detect_face(gray, ff)) {
            ++no_face;
            if (no_face % 15 == 0)
                printf("  [IR Face] No face detected – centre face in "
                       "camera view...\n");
            continue;
        }

        if (!liveness_ok(ff.face)) {
            ++rejected_liveness;
            if (rejected_liveness % 5 == 0)
                printf("  [IR Face] Liveness check failed (lap_var=%.1f < "
                       "%.1f) – ensure good IR lighting\n",
                       ff.lap_var, LAP_MIN);
            continue;
        }

        samples.push_back(face_to_feature(ff.face));
        int n = (int)samples.size();
        /* ASCII progress bar */
        int bars = (n * 20) / ENROLL_FRAMES;
        printf("  [IR Face] [%-20.*s] %d/%d\r",
               bars, "====================", n, ENROLL_FRAMES);
        fflush(stdout);
    }
    printf("\n  [IR Face] Collected %d samples – computing template...\n",
           ENROLL_FRAMES);

    /* Average samples into a single mean template */
    std::vector<float> templ(FEAT_DIM, 0.0f);
    for (const auto &s : samples)
        for (int i = 0; i < FEAT_DIM; ++i)
            templ[i] += s[i] / (float)ENROLL_FRAMES;

    /* Re-normalise the averaged vector */
    float norm = 0.0f;
    for (float v : templ) norm += v * v;
    norm = std::sqrt(norm);
    if (norm > 1e-6f) for (float &v : templ) v /= norm;

    /* Encrypt and save */
    char out_path[512];
    snprintf(out_path, sizeof(out_path), LH_FACE_EMB_FILE_FMT, username);
    if (encrypt_embedding(templ, pubkey_der, pubkey_der_len, username,
                          out_path) != 0) {
        fprintf(stderr, "[linuxhello/face] Failed to save face template\n");
        return LH_FACE_ERR_CRYPTO;
    }

    printf("  [IR Face] Face template saved and encrypted (%d-dim LBP, "
           "AES-256-GCM).\n", FEAT_DIM);
    return LH_FACE_OK;
}

/* ── lh_ir_camera_test ───────────────────────────────────── */
/**
 * lh_ir_camera_test – Quick pre-enrollment sanity check for the IR camera.
 *
 * Uses the same auto-detection logic as open_ir_camera(): tries the
 * configured default device first, then scans /dev/video0 through
 * /dev/video<LH_IR_DEVICE_MAX>.  Verifies that at least one device can
 * deliver frames.
 *
 * Returns:
 *   LH_FACE_OK          device opened and at least one frame received
 *   LH_FACE_ERR_DEVICE  no suitable device found
 *   LH_FACE_ERR_NO_FRAME device opened but no frame arrived (driver issue)
 */
static constexpr int LH_CAM_TEST_FRAMES     = 10;
static constexpr int LH_CAM_TEST_TIMEOUT_MS = 3000; /* 3 seconds */

int lh_ir_camera_test(void)
{
    fprintf(stderr,
            "[lh_ir_camera_test] probing for IR camera "
            "(default %s, scanning /dev/video0..%d) ...\n",
            LH_IR_DEVICE, LH_IR_DEVICE_MAX);

    /* 1. Try to open the camera via auto-detection */
    cv::VideoCapture cap;
    if (!open_ir_camera(cap)) {
        fprintf(stderr,
                "[lh_ir_camera_test] ERROR: no suitable camera found.\n"
                "  Hints:\n"
                "    ls -la /dev/video*              – list available video nodes\n"
                "    v4l2-ctl --list-devices         – list V4L2 devices\n"
                "    sudo dmesg | grep -iE 'uvc|video|camera' – driver output\n"
                "    sudo usermod -aG video $USER    – add user to video group\n");
        return LH_FACE_ERR_DEVICE;
    }

    /*
     * 2. Attempt to read frames within the timeout window.
     *    Some cameras need a few frames to warm up before delivering
     *    valid data, so we try up to LH_CAM_TEST_FRAMES times.
     */
    using Clock    = std::chrono::steady_clock;
    using Ms       = std::chrono::milliseconds;
    auto deadline  = Clock::now() + Ms(LH_CAM_TEST_TIMEOUT_MS);
    int  attempts  = 0;
    bool got_frame = false;

    while (Clock::now() < deadline && attempts < LH_CAM_TEST_FRAMES) {
        cv::Mat frame;
        bool ok = cap.read(frame);
        attempts++;

        if (ok && !frame.empty()) {
            /* Verify the frame has plausible dimensions */
            if (frame.cols > 0 && frame.rows > 0) {
                fprintf(stderr,
                        "[lh_ir_camera_test] OK – frame %d: %dx%d ch=%d\n",
                        attempts, frame.cols, frame.rows, frame.channels());
                got_frame = true;
                break;
            }
        }
    }

    cap.release();

    if (!got_frame) {
        fprintf(stderr,
                "[lh_ir_camera_test] ERROR: camera opened but no valid frame "
                "received in %d ms (%d attempt(s)).\n"
                "  Hints:\n"
                "    Check IR illuminator LEDs are on during capture.\n"
                "    Check dmesg for timeout or underrun messages.\n",
                LH_CAM_TEST_TIMEOUT_MS, attempts);
        return LH_FACE_ERR_NO_FRAME;
    }

    fprintf(stderr,
            "[lh_ir_camera_test] IR camera is functional.\n");
    return LH_FACE_OK;
}

/* ── lh_face_verify ──────────────────────────────────────── */
lh_bio_result_t lh_face_verify(const char    *username,
                                const uint8_t *pubkey_der,
                                size_t         pubkey_der_len)
{
    /* Load and decrypt enrolled template */
    char emb_path[512];
    snprintf(emb_path, sizeof(emb_path), LH_FACE_EMB_FILE_FMT, username);

    if (access(emb_path, F_OK) != 0) return LH_BIO_NOTENROLLED;

    std::vector<float> stored;
    if (decrypt_embedding(emb_path, pubkey_der, pubkey_der_len,
                          username, stored) != 0)
        return LH_BIO_ERROR;

    /* Open IR camera */
    cv::VideoCapture cap;
    if (!open_ir_camera(cap)) return LH_BIO_ERROR;

    using Clock = std::chrono::steady_clock;
    auto deadline = Clock::now() + std::chrono::seconds(LH_FACE_TIMEOUT_S);

    while (Clock::now() < deadline) {
        cv::Mat raw;
        if (!cap.read(raw) || raw.empty()) continue;

        cv::Mat gray = to_gray(raw);
        FaceFrame ff;
        if (!detect_face(gray, ff)) continue;
        if (!liveness_ok(ff.face))  continue;

        double dist = chi2(face_to_feature(ff.face), stored);
        if (dist <= CHI2_THRESH) return LH_BIO_OK;
    }

    return LH_BIO_TIMEOUT;
}

} /* extern "C" */
