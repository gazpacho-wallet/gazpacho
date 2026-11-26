/*
 * The Esplora HTTP backend: a gz_chain that asks one chain server speaking
 * the Esplora block-explorer interface (mempool.space, blockstream.info, or
 * the user's own).
 */
#ifndef GAZPACHO_CHAIN_ESPLORA_H
#define GAZPACHO_CHAIN_ESPLORA_H

#include "gazpacho/chain.h"
#include "gazpacho/chain_http.h"

#ifdef __cplusplus
extern "C" {
#endif

#define GZ_ESPLORA_URL_MAX 200

typedef struct gz_esplora_config {
  /* Base address without a trailing slash, for example
   * "https://mempool.space/signet/api". Must start with https://. Plain
   * http:// is accepted only when the host is this machine (localhost,
   * 127.0.0.1 or [::1]), for a server the user runs. Only letters, digits
   * and . - _ ~ : / characters (and the brackets of [::1]); no user
   * information ("user@"); at most GZ_ESPLORA_URL_MAX characters. The host
   * is put into its one canonical form by gz_host_normalise (case, one
   * trailing dot) and refused if it has none; requests are sent to the
   * canonical address. Copied. */
  const char *base_url;
  /* Optional, but server lists should always give it. Who runs this
   * server, for counting independent operators in the comparing backend.
   * NULL: derived from the host name by gz_operator_from_host, a rule of
   * thumb. Must be in canonical form (gz_operator_name_valid): lowercase
   * letters, digits, dots and dashes, at most GZ_OPERATOR_MAX - 1
   * characters. Copied. */
  const char *operator_id;
  /* Limit for each single request. */
  uint32_t timeout_ms;
  /* Tries per request, counting the first. Retries happen when the server
   * could not be reached or answered 429 or 5xx. A broadcast is not retried
   * after a timeout or a 5xx, because the server may have acted on it. */
  uint32_t max_attempts;
  /* Wait before the second try; doubles for each later try, up to 30 s. */
  uint32_t backoff_ms;
  /* Least time between the starts of two requests to this server. */
  uint32_t min_interval_ms;
  /* Size of the one response buffer, allocated at creation. No response
   * larger than this is ever accepted, and most calls use a much smaller
   * cap of their own. */
  size_t max_response_bytes;
} gz_esplora_config;

/* Fills the defaults: 15 s timeout, 3 attempts, 500 ms first backoff,
 * 250 ms between requests, 512 KiB response buffer. base_url and
 * operator_id are left NULL. */
void gz_esplora_config_default(gz_esplora_config *cfg);

/*
 * Creates the backend. `http` is copied; its ctx must outlive the backend.
 * Returns GZ_CHAIN_INVALID_ARG for a bad configuration, GZ_CHAIN_NO_MEMORY,
 * or GZ_CHAIN_OK with *out ready. Free with gz_chain_destroy.
 *
 * Creating a backend sends nothing. It does not check which network the
 * server is on: gz_chain_check_network, gz_chain_confirm_tx and the
 * comparing backend do.
 */
gz_chain_result gz_esplora_create(const gz_esplora_config *cfg, const gz_http *http,
                                  gz_chain *out);

/*
 * The package-endpoint probe (plan S12, step 1). Sends GZ_ESPLORA_PROBE_BODY,
 * which is not JSON and so cannot be read as a list of transactions, to the
 * package endpoint: nothing can be broadcast. A server with the endpoint
 * refuses it with 400; one without answers 404 (or 405).
 */
#define GZ_ESPLORA_PROBE_BODY "gazpacho package probe: not a package"
/* A path no Esplora server has, asked first with the same body: it must
 * answer 404 or 405, or a 400 elsewhere would prove nothing. */
#define GZ_ESPLORA_PROBE_CONTROL_PATH "/txs/gazpacho-probe-no-such-path"
#define GZ_ESPLORA_PROBE_PATH_MAX 40

typedef struct gz_package_probe {
  /* GZ_CHAIN_OK: the endpoint is there (400 to the probe), at `path`.
   * GZ_CHAIN_UNSUPPORTED: 404 or 405 at every path tried.
   * GZ_CHAIN_REJECTED: another 4xx; cannot tell (the words are in `reason`).
   * GZ_CHAIN_MALFORMED: a 2xx or other status to a body that is no package.
   * GZ_CHAIN_UNREACHABLE, GZ_CHAIN_TOO_LARGE: as for any request. */
  gz_chain_result result;
  long server_status; /* HTTP status of the last answer, or 0 if not reached */
  char path[GZ_ESPLORA_PROBE_PATH_MAX]; /* the path of the last answer, e.g. "/txs/package" */
  /* The server's words, printable ASCII, zero-terminated. */
  char reason[GZ_REASON_MAX];
} gz_package_probe;

/* Probes one Esplora backend made by gz_esplora_create (anything else is
 * GZ_CHAIN_INVALID_ARG and nothing is sent). Tries the same paths, in the
 * same order, as gz_chain_broadcast_package. `out` is filled whatever the
 * result and out->result equals the return value. Safe on every network:
 * the body is never a transaction. */
gz_chain_result gz_esplora_probe_package(const gz_chain *c, gz_package_probe *out);

#ifdef __cplusplus
}
#endif

#endif /* GAZPACHO_CHAIN_ESPLORA_H */
