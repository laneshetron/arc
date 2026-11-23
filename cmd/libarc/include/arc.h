/*
 * libarc: the ARC tunnel client as a C library, for a packet tunnel
 * provider (NetworkExtension) on macOS and iOS.
 *
 * The provider owns the utun: it creates it, and applies the address, MTU,
 * routes and DNS through NEPacketTunnelNetworkSettings. libarc reads and
 * writes packets on its descriptor and runs the session to the relay over
 * its own sockets, which the system keeps out of the tunnel.
 *
 * Strings passed in are UTF-8 and NUL-terminated, and libarc copies what
 * it keeps. Strings returned are owned by the caller and freed with
 * arc_free.
 */
#ifndef ARC_H
#define ARC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * An event is a JSON object whose "event" member names its kind:
 *
 *   "network"  The relay assigned the tunnel's network, on each new
 *              session (a reconnect may lease another address):
 *              {"event":"network","address":"10.77.0.2","prefix":24,
 *               "mtu":1300,"dns":"10.77.0.53"}
 *              dns is "" when the relay offers no resolver. Return 0 once
 *              the settings are applied, or nonzero to end the tunnel; the
 *              tunnel waits for the return, and carries no traffic until
 *              then.
 *   "log"      A log record: {"event":"log","time":...,"level":"INFO",
 *              "msg":..., plus the record's own members}. The return
 *              value is ignored.
 *   "stopped"  The tunnel ended: {"event":"stopped"} after arc_stop, or
 *              {"event":"stopped","error":"..."} when it failed on its own.
 *              It is the last event. The return value is ignored.
 *
 * The callback runs on a thread libarc owns, never the one that called
 * arc_start, and one event at a time, so a slow callback delays the
 * tunnel. Events may begin as soon as arc_start has set *handle, possibly
 * before arc_start returns, so whatever the callback reads through context
 * must be ready before the call. The callback must not call arc_stop for
 * its own tunnel, which
 * waits for the callback to return. No event arrives after arc_stop
 * returns. event_json is valid only during the call.
 */
typedef int (*arc_event_fn)(void *context, const char *event_json);

/*
 * arc_start starts a tunnel and returns NULL, setting *handle; or returns an
 * error message and leaves *handle alone.
 *
 * config_json is a JSON object (unknown members are an error):
 *
 *   relay              required  the relay's session address, "ip:port"
 *   relay_key          required  the relay's static public key, base64
 *   token              required  the access token
 *   private_key        required  this device's static private key, base64
 *                                (see arc_generate_key)
 *   no_udp             bool      reach the relay only through tls or front
 *   censorship         bool      no UDP to an address a stream carrier uses
 *   tls                "host:port"  a TLS/TCP carrier, used while no UDP
 *                                path works
 *   tls_ca             path to PEM certificates to trust for tls
 *   tls_server_name    name to verify the relay's certificate against
 *   tls_cover          server name to pose as (skips verification unless
 *                      tls_ca is set; ARC authenticates the relay itself)
 *   tls_fingerprint    chrome, edge, safari, ios or firefox
 *   tls_fragment       split the ClientHello into segments of this size
 *   front              "host:port"  the relay's HTTPS front
 *   stream_rotate_bytes  move a stream carrier to a fresh connection after
 *                      receiving this much; 0 learns the cap
 *   redundancy         "off" (default), "auto" or "always"
 *   fec                "auto" (default), "off" or "always"
 *   split_tcp          "off" (default), "auto" or "always"
 *   status_interval    seconds between path status logs; 0 (default): off
 *   log_level          "debug", "info" (default), "warn" or "error"
 *   journal            path of a diagnostics journal to keep
 *   share_diagnostics  bool  upload the journal to the relay's operator
 *
 * tun_fd is the provider's utun descriptor. libarc takes ownership of it,
 * and closes it when the tunnel stops or arc_start fails. callback receives
 * the tunnel's events with context as its first argument.
 */
char *arc_start(const char *config_json, int tun_fd, arc_event_fn callback, void *context, int64_t *handle);

/*
 * arc_stop stops the tunnel, waits until it has, and frees the handle. The
 * "stopped" event is delivered before it returns, unless the tunnel had
 * already stopped on its own. Calls for the same handle from several
 * threads all wait for that one shutdown. Call it for every handle
 * arc_start set, even after a "stopped" event. An unknown handle is
 * ignored.
 */
void arc_stop(int64_t handle);

/*
 * arc_generate_key returns a new static key pair as
 * {"private_key":"...","public_key":"..."}, both base64.
 */
char *arc_generate_key(void);

/* arc_version returns the version libarc was built from. */
char *arc_version(void);

/* arc_free frees a string libarc returned. NULL is ignored. */
void arc_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* ARC_H */
