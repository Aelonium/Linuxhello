/*
 * fprintd_stub.c – Stub biometric client when GLib/fprintd is unavailable
 *
 * When compiled with LH_NO_BIOMETRIC, all biometric functions return
 * "not available" so the rest of the system falls through to PIN-only mode.
 */

#include "fprintd_client.h"
#include <stdio.h>

lh_bio_result_t lh_bio_verify(const char *username)
{
    (void)username;
    return LH_BIO_ERROR; /* fprintd not available at build time */
}

int lh_bio_enroll(const char *username)
{
    (void)username;
    fprintf(stderr, "[linuxhello] biometric support not compiled in "
                    "(install libglib2.0-dev and rebuild)\n");
    return -1;
}

bool lh_bio_is_enrolled(const char *username)
{
    (void)username;
    return false;
}

int lh_bio_delete_enrolled(const char *username)
{
    (void)username;
    return 0; /* no-op */
}
