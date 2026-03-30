/*
 * lhd.h – LinuxHello Auth Daemon public interface
 *
 * The daemon (lhd) is the privileged broker between the PAM module
 * and the TPM / biometric subsystems.  It runs as root and listens
 * on a Unix domain socket (LH_DAEMON_SOCKET).
 *
 * Responsibilities:
 *   - Generate fresh challenges (nonces) for authentication requests
 *   - Perform biometric verification via fprintd (gesture gate)
 *   - Trigger TPM signing using the user's persisted key
 *   - Verify the resulting signature against the stored public key
 *   - Maintain and enforce the software-layer lockout counter
 *   - Log all authentication events to journald / syslog
 */

#ifndef LHD_H
#define LHD_H

#include <stdbool.h>
#include "../common/linuxhello.h"

/** lhd_config – Runtime configuration for the daemon */
typedef struct lhd_config {
    const char *socket_path;     /* defaults to LH_DAEMON_SOCKET         */
    bool        foreground;      /* don't daemonise (for debugging)       */
    bool        debug;           /* verbose logging                       */
} lhd_config_t;

/**
 * lhd_run – Main entry point.  Initialises the socket, drops as many
 * privileges as possible (though root is needed for TPM & storage), and
 * enters the accept loop.  Does not return unless a fatal error occurs.
 *
 * @returns 0 on clean exit, -1 on error
 */
int lhd_run(const lhd_config_t *config);

/**
 * lhd_handle_auth_request – Process one authentication request on @client_fd.
 *
 * This is the core authentication state machine:
 *   1. Read LH_MSG_AUTH_REQUEST, extract username
 *   2. Check lockout state (software counter + TPM DA)
 *   3. Load credential from storage
 *   4. Generate a fresh challenge and send LH_MSG_CHALLENGE
 *   5. Trigger biometric verification in parallel (if enrolled)
 *   6. Wait for PIN response from client
 *   7. Open TPM policy session (PIN authorisation)
 *   8. Sign the challenge with the TPM key
 *   9. Verify the signature with the stored public key
 *   10. Record success/failure; update lockout counter
 *   11. Send LH_MSG_AUTH_RESULT
 *
 * @param client_fd  Connected client socket
 * @param debug      Enable verbose logging
 */
void lhd_handle_auth_request(int client_fd, bool debug);

#endif /* LHD_H */
