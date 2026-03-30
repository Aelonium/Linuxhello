/*
 * fprintd_client.c – fprintd D-Bus client implementation
 *
 * Uses the GLib D-Bus API (libglib-2.0, libgio-2.0) to communicate
 * with org.freedesktop.DBus.fprintd (net.reactivated.Fprint).
 *
 * D-Bus interface summary used here:
 *   net.reactivated.Fprint.Manager – list devices
 *   net.reactivated.Fprint.Device  – Claim(), VerifyStart("any"), ...
 */

#include "fprintd_client.h"

#include <stdio.h>
#include <string.h>
#include <gio/gio.h>       /* GLib D-Bus: package libglib2.0-dev */

#define FPRINTD_BUS_NAME  "net.reactivated.Fprint"
#define FPRINTD_MGR_OBJ   "/net/reactivated/Fprint/Manager"
#define FPRINTD_MGR_IFACE "net.reactivated.Fprint.Manager"
#define FPRINTD_DEV_IFACE "net.reactivated.Fprint.Device"

/* ── Internal helpers ────────────────────────────────────── */

static GDBusProxy *get_manager(GDBusConnection *conn, GError **err)
{
    return g_dbus_proxy_new_sync(
        conn,
        G_DBUS_PROXY_FLAGS_NONE, NULL,
        FPRINTD_BUS_NAME, FPRINTD_MGR_OBJ, FPRINTD_MGR_IFACE,
        NULL, err);
}

static char *get_default_device_path(GDBusProxy *mgr, GError **err)
{
    GVariant *result = g_dbus_proxy_call_sync(
        mgr, "GetDefaultDevice", NULL,
        G_DBUS_CALL_FLAGS_NONE, -1, NULL, err);
    if (!result) return NULL;

    const char *path = NULL;
    g_variant_get(result, "(&o)", &path);
    char *ret = g_strdup(path);
    g_variant_unref(result);
    return ret;
}

static GDBusProxy *get_device(GDBusConnection *conn,
                               const char      *device_path,
                               GError         **err)
{
    return g_dbus_proxy_new_sync(
        conn,
        G_DBUS_PROXY_FLAGS_NONE, NULL,
        FPRINTD_BUS_NAME, device_path, FPRINTD_DEV_IFACE,
        NULL, err);
}

/* ── lh_bio_verify ───────────────────────────────────────── */

lh_bio_result_t lh_bio_verify(const char *username)
{
    GError          *err  = NULL;
    GDBusConnection *conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
    if (!conn) {
        fprintf(stderr, "[linuxhello] D-Bus connect failed: %s\n",
                err ? err->message : "unknown");
        if (err) g_error_free(err);
        return LH_BIO_ERROR;
    }

    GDBusProxy *mgr = get_manager(conn, &err);
    if (!mgr) {
        fprintf(stderr, "[linuxhello] fprintd manager unavailable: %s\n",
                err ? err->message : "unknown");
        if (err) g_error_free(err);
        g_object_unref(conn);
        return LH_BIO_ERROR;
    }

    char *dev_path = get_default_device_path(mgr, &err);
    g_object_unref(mgr);
    if (!dev_path) {
        if (err) g_error_free(err);
        g_object_unref(conn);
        return LH_BIO_ERROR;
    }

    GDBusProxy *dev = get_device(conn, dev_path, &err);
    g_free(dev_path);
    if (!dev) {
        if (err) g_error_free(err);
        g_object_unref(conn);
        return LH_BIO_ERROR;
    }

    /* Claim the device for the user */
    GVariant *result = g_dbus_proxy_call_sync(
        dev, "Claim",
        g_variant_new("(s)", username),
        G_DBUS_CALL_FLAGS_NONE, -1, NULL, &err);
    if (!result) {
        if (err && strstr(err->message, "No enrolled prints"))
        {
            g_error_free(err);
            g_object_unref(dev);
            g_object_unref(conn);
            return LH_BIO_NOTENROLLED;
        }
        fprintf(stderr, "[linuxhello] fprintd Claim failed: %s\n",
                err ? err->message : "unknown");
        if (err) g_error_free(err);
        g_object_unref(dev);
        g_object_unref(conn);
        return LH_BIO_ERROR;
    }
    g_variant_unref(result);

    /* Start verification – "any" means any enrolled finger */
    result = g_dbus_proxy_call_sync(
        dev, "VerifyStart",
        g_variant_new("(s)", "any"),
        G_DBUS_CALL_FLAGS_NONE, -1, NULL, &err);
    if (!result) {
        fprintf(stderr, "[linuxhello] fprintd VerifyStart failed: %s\n",
                err ? err->message : "unknown");
        if (err) g_error_free(err);
        g_dbus_proxy_call_sync(dev, "Release", NULL,
                               G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL);
        g_object_unref(dev);
        g_object_unref(conn);
        return LH_BIO_ERROR;
    }
    g_variant_unref(result);

    /*
     * Poll for VerifyFingerStatus signal.
     * In a production implementation this would use a GMainLoop /
     * async signal subscription; here we use a timed synchronous poll
     * to keep the code self-contained.
     *
     * The VerifyStatus signal carries (s: result, b: done).
     * Possible result strings: "verify-match", "verify-no-match",
     * "verify-retry-scan-too-short", "verify-swipe-too-fast", …
     */
    lh_bio_result_t bio_rc = LH_BIO_TIMEOUT;
    GMainContext *ctx = g_main_context_new();
    GMainLoop    *loop = g_main_loop_new(ctx, FALSE);

    /*
     * NOTE: A full implementation subscribes to the fprintd VerifyStatus
     * D-Bus signal and drives a GMainLoop with a timeout source.
     * The structure below shows the correct integration points; signal
     * subscription requires g_dbus_connection_signal_subscribe() and a
     * callback that updates bio_rc and quits the loop.
     *
     * For brevity the blocking call path is shown; integrators should
     * convert this to the async signal-driven pattern.
     */
    (void)loop;   /* suppress unused-variable warning in skeleton */
    (void)ctx;

    /*
     * Simplified blocking poll: read VerifyStatus via a property read.
     * Real code must subscribe to the VerifyStatus *signal* because
     * the "Status" property only reflects the latest static state.
     */
    GVariant *status = g_dbus_proxy_get_cached_property(dev, "Status");
    if (status) {
        const char *s = g_variant_get_string(status, NULL);
        if (strcmp(s, "verify-match") == 0)      bio_rc = LH_BIO_OK;
        else if (strcmp(s, "verify-no-match") == 0) bio_rc = LH_BIO_NOMATCH;
        g_variant_unref(status);
    }

    /* Stop verification and release the device */
    g_dbus_proxy_call_sync(dev, "VerifyStop", NULL,
                           G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL);
    g_dbus_proxy_call_sync(dev, "Release", NULL,
                           G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL);

    g_main_loop_unref(loop);
    g_main_context_unref(ctx);
    g_object_unref(dev);
    g_object_unref(conn);
    return bio_rc;
}

/* ── lh_bio_enroll ───────────────────────────────────────── */

int lh_bio_enroll(const char *username)
{
    GError          *err  = NULL;
    GDBusConnection *conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
    if (!conn) {
        if (err) g_error_free(err);
        return -1;
    }

    GDBusProxy *mgr = get_manager(conn, &err);
    if (!mgr) { if (err) g_error_free(err); g_object_unref(conn); return -1; }

    char *dev_path = get_default_device_path(mgr, &err);
    g_object_unref(mgr);
    if (!dev_path) { if (err) g_error_free(err); g_object_unref(conn); return -1; }

    GDBusProxy *dev = get_device(conn, dev_path, &err);
    g_free(dev_path);
    if (!dev) { if (err) g_error_free(err); g_object_unref(conn); return -1; }

    GVariant *result = g_dbus_proxy_call_sync(
        dev, "Claim",
        g_variant_new("(s)", username),
        G_DBUS_CALL_FLAGS_NONE, -1, NULL, &err);
    if (!result) {
        fprintf(stderr, "[linuxhello] fprintd Claim (enroll) failed: %s\n",
                err ? err->message : "unknown");
        if (err) g_error_free(err);
        g_object_unref(dev);
        g_object_unref(conn);
        return -1;
    }
    g_variant_unref(result);

    /*
     * EnrollStart("right-index-finger") – finger name is advisory.
     * A full implementation drives the EnrollStatus signal loop and
     * prompts the user to rescan until enrollment is complete.
     */
    result = g_dbus_proxy_call_sync(
        dev, "EnrollStart",
        g_variant_new("(s)", "right-index-finger"),
        G_DBUS_CALL_FLAGS_NONE, -1, NULL, &err);
    int rc = 0;
    if (!result) {
        fprintf(stderr, "[linuxhello] fprintd EnrollStart failed: %s\n",
                err ? err->message : "unknown");
        if (err) g_error_free(err);
        rc = -1;
    } else {
        g_variant_unref(result);
        printf("[linuxhello] Fingerprint enrollment started – "
               "follow fprintd prompts.\n");
        /* TODO: subscribe to EnrollStatus signal for completion */
    }

    g_dbus_proxy_call_sync(dev, "EnrollStop", NULL,
                           G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL);
    g_dbus_proxy_call_sync(dev, "Release", NULL,
                           G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL);

    g_object_unref(dev);
    g_object_unref(conn);
    return rc;
}

/* ── lh_bio_is_enrolled ──────────────────────────────────── */

bool lh_bio_is_enrolled(const char *username)
{
    GError          *err  = NULL;
    GDBusConnection *conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
    if (!conn) { if (err) g_error_free(err); return false; }

    GDBusProxy *mgr = get_manager(conn, &err);
    if (!mgr) { if (err) g_error_free(err); g_object_unref(conn); return false; }

    char *dev_path = get_default_device_path(mgr, &err);
    g_object_unref(mgr);
    if (!dev_path) {
        if (err) g_error_free(err);
        g_object_unref(conn);
        return false;
    }

    GDBusProxy *dev = get_device(conn, dev_path, &err);
    g_free(dev_path);
    if (!dev) { if (err) g_error_free(err); g_object_unref(conn); return false; }

    /*
     * ListEnrolledFingers returns an array of finger name strings.
     * If the array is non-empty the user is enrolled.
     */
    GVariant *result = g_dbus_proxy_call_sync(
        dev, "ListEnrolledFingers",
        g_variant_new("(s)", username),
        G_DBUS_CALL_FLAGS_NONE, -1, NULL, &err);

    bool enrolled = false;
    if (result) {
        GVariant *fingers = g_variant_get_child_value(result, 0);
        enrolled = (g_variant_n_children(fingers) > 0);
        g_variant_unref(fingers);
        g_variant_unref(result);
    } else {
        if (err) g_error_free(err);
    }

    g_object_unref(dev);
    g_object_unref(conn);
    return enrolled;
}

/* ── lh_bio_delete_enrolled ──────────────────────────────── */

int lh_bio_delete_enrolled(const char *username)
{
    GError          *err  = NULL;
    GDBusConnection *conn = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &err);
    if (!conn) { if (err) g_error_free(err); return -1; }

    GDBusProxy *mgr = get_manager(conn, &err);
    if (!mgr) { if (err) g_error_free(err); g_object_unref(conn); return -1; }

    char *dev_path = get_default_device_path(mgr, &err);
    g_object_unref(mgr);
    if (!dev_path) { if (err) g_error_free(err); g_object_unref(conn); return -1; }

    GDBusProxy *dev = get_device(conn, dev_path, &err);
    g_free(dev_path);
    if (!dev) { if (err) g_error_free(err); g_object_unref(conn); return -1; }

    GVariant *result = g_dbus_proxy_call_sync(
        dev, "DeleteEnrolledFingers",
        g_variant_new("(s)", username),
        G_DBUS_CALL_FLAGS_NONE, -1, NULL, &err);
    int rc = 0;
    if (!result) {
        fprintf(stderr, "[linuxhello] fprintd DeleteEnrolledFingers failed: %s\n",
                err ? err->message : "unknown");
        if (err) g_error_free(err);
        rc = -1;
    } else {
        g_variant_unref(result);
    }

    g_object_unref(dev);
    g_object_unref(conn);
    return rc;
}
