/*
 * gz-chain: ask chain servers by hand and see each server's answer next to
 * the combined verdict. For manual use and for the walkthroughs.
 *
 *   gz-chain [--network NET] [--server URL]... COMMAND [ARGS]
 *
 * Exit status: 0 the servers agreed on an answer; 1 no agreed answer
 * (disagreement, too few servers, failed proof, refusal); 2 bad usage.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gazpacho/chain.h"
#include "gazpacho/chain_esplora.h"
#include "gazpacho/chain_http.h"
#include "gazpacho/chain_multi.h"

#define MAX_TX_BYTES 400000
#define MAX_OUTPUTS 256

/* The servers listed in docs/CHAIN-SERVERS.md, per network. */
static const char *const DEFAULT_SIGNET[] = {"https://mempool.space/signet/api",
                                             "https://blockstream.info/signet/api", NULL};
static const char *const DEFAULT_TESTNET4[] = {"https://mempool.space/testnet4/api", NULL};
static const char *const DEFAULT_TESTNET3[] = {"https://blockstream.info/testnet/api", NULL};
static const char *const DEFAULT_MAINNET[] = {"https://mempool.space/api",
                                              "https://blockstream.info/api", NULL};

static const char *const *default_servers(gz_network n) {
  switch (n) {
    case GZ_NET_SIGNET: return DEFAULT_SIGNET;
    case GZ_NET_TESTNET4: return DEFAULT_TESTNET4;
    case GZ_NET_TESTNET3: return DEFAULT_TESTNET3;
    case GZ_NET_MAINNET: return DEFAULT_MAINNET;
  }
  return DEFAULT_SIGNET;
}

static void usage(FILE *to) {
  fprintf(to,
          "usage: gz-chain [--network signet|testnet4|testnet|mainnet] [--server URL]... COMMAND\n"
          "\n"
          "commands:\n"
          "  tip                    best block height and hash\n"
          "  tx TXID                is the transaction known, in the mempool or confirmed\n"
          "  script HEX             unspent outputs paying this scriptPubKey\n"
          "  outspend TXID VOUT     is this output spent, and by what\n"
          "  proof TXID             fetch the Merkle proof and check it against the block header\n"
          "  fee                    fee estimates by confirmation target\n"
          "  broadcast HEX          send a transaction (refused on mainnet)\n"
          "\n"
          "The network defaults to signet. Without --server, the servers listed in\n"
          "docs/CHAIN-SERVERS.md for the network are used. An answer counts only when at\n"
          "least two servers give it and none contradicts it.\n");
}

typedef struct app {
  gz_network network;
  size_t n;
  const char *urls[GZ_MULTI_MAX_SERVERS];
  gz_chain servers[GZ_MULTI_MAX_SERVERS];
  gz_chain multi;
  gz_http http;
} app;

static void print_hash(const uint8_t h[GZ_HASH_LEN]) {
  char hex[2 * GZ_HASH_LEN + 1];
  gz_hash_to_hex(h, hex);
  fputs(hex, stdout);
}

static int verdict_line(gz_chain_result r) {
  printf("verdict: %s", gz_chain_result_name(r));
  switch (r) {
    case GZ_CHAIN_OK: printf(" (servers agree)\n"); return 0;
    case GZ_CHAIN_NOT_FOUND: printf(" (servers agree it does not exist)\n"); return 1;
    case GZ_CHAIN_DISAGREE: printf(" (treat as NOT confirmed)\n"); return 1;
    case GZ_CHAIN_NO_QUORUM:
      printf(" (fewer than two servers answered: cannot confirm)\n");
      return 1;
    default: printf("\n"); return 1;
  }
}

static void print_tx_status(const gz_tx_status *s) {
  switch (s->state) {
    case GZ_TX_UNKNOWN: printf("unknown to the server"); break;
    case GZ_TX_MEMPOOL: printf("in the mempool, unconfirmed"); break;
    case GZ_TX_CONFIRMED:
      printf("confirmed at height %lu in block ", (unsigned long)s->height);
      print_hash(s->block_hash);
      printf(", %lu confirmations (tip %lu)", (unsigned long)s->confirmations,
             (unsigned long)s->tip_height);
      break;
  }
}

static void print_output(const gz_chain_output *o) {
  print_hash(o->txid);
  printf(":%lu  %llu sat  ", (unsigned long)o->vout, (unsigned long long)o->value);
  if (o->confirmed) {
    printf("confirmed at height %lu", (unsigned long)o->height);
  } else {
    printf("in the mempool");
  }
}

static void print_outspend(const gz_outspend *o) {
  if (!o->spent) {
    printf("not spent");
    return;
  }
  printf("spent by ");
  print_hash(o->spender_txid);
  printf(" input %lu, ", (unsigned long)o->spender_vin);
  if (o->confirmed) {
    printf("confirmed at height %lu in block ", (unsigned long)o->height);
    print_hash(o->block_hash);
  } else {
    printf("in the mempool");
  }
}

static void print_fees(const gz_fee_estimates *f) {
  for (size_t i = 0; i < f->count; i++) {
    printf("%s%u:%llu.%03llu", i ? " " : "", (unsigned)f->entries[i].target,
           (unsigned long long)(f->entries[i].sat_per_kvb / 1000),
           (unsigned long long)(f->entries[i].sat_per_kvb % 1000));
  }
}

/* Prints every server's line for the last call on the comparing backend. */
static void print_report(const app *a) {
  const gz_multi_report *rep = gz_multi_last_report(&a->multi);
  if (rep == NULL) return;
  for (size_t i = 0; i < rep->server_count; i++) {
    const gz_multi_answer *ans = &rep->answers[i];
    printf("  %s\n    ", a->urls[i]);
    if (rep->call == GZ_CALL_BROADCAST) {
      const gz_broadcast_result *b = &ans->u.broadcast;
      if (ans->result == GZ_CHAIN_OK) {
        printf("accepted ");
        print_hash(b->txid);
      } else {
        printf("%s (HTTP %ld)%s%s", gz_chain_result_name(ans->result), b->server_status,
               b->reason[0] ? ": " : "", b->reason);
      }
      printf("\n");
      continue;
    }
    if (ans->result != GZ_CHAIN_OK) {
      printf("%s\n", gz_chain_result_name(ans->result));
      continue;
    }
    switch (rep->call) {
      case GZ_CALL_TIP:
        printf("height %lu  ", (unsigned long)ans->u.tip.height);
        print_hash(ans->u.tip.hash);
        break;
      case GZ_CALL_TX_STATUS: print_tx_status(&ans->u.tx_status); break;
      case GZ_CALL_SCRIPT_OUTPUTS:
        printf("%zu unspent output(s)", ans->u.outputs.count);
        for (size_t k = 0; k < ans->u.outputs.count; k++) {
          printf("\n    ");
          print_output(&ans->u.outputs.items[k]);
        }
        break;
      case GZ_CALL_OUTSPEND: print_outspend(&ans->u.outspend); break;
      case GZ_CALL_FEE_ESTIMATES: print_fees(&ans->u.fees); break;
      default: printf("ok"); break;
    }
    printf("\n");
  }
}

static bool parse_txid(const char *s, uint8_t out[GZ_HASH_LEN]) {
  if (!gz_hash_from_hex(s, strlen(s), out)) {
    fprintf(stderr, "gz-chain: a txid is 64 lowercase hex characters\n");
    return false;
  }
  return true;
}

static int cmd_tip(app *a) {
  gz_chain_tip tip;
  gz_chain_result r = gz_chain_tip_get(&a->multi, &tip);
  print_report(a);
  int rc = verdict_line(r);
  if (r == GZ_CHAIN_OK) {
    printf("tip: height %lu  ", (unsigned long)tip.height);
    print_hash(tip.hash);
    printf("\n");
  }
  return rc;
}

static int cmd_tx(app *a, const char *arg) {
  uint8_t txid[GZ_HASH_LEN];
  gz_tx_status st;
  if (!parse_txid(arg, txid)) return 2;
  gz_chain_result r = gz_chain_tx_status(&a->multi, txid, &st);
  print_report(a);
  int rc = verdict_line(r);
  if (r == GZ_CHAIN_OK) {
    printf("transaction: ");
    print_tx_status(&st);
    printf("\n");
    if (st.state == GZ_TX_CONFIRMED)
      printf("note: this is the servers' claim; `gz-chain proof` checks it against the header\n");
  }
  return rc;
}

static int cmd_script(app *a, const char *arg) {
  static uint8_t script[GZ_SCRIPT_MAX_LEN];
  static gz_chain_output outs[MAX_OUTPUTS];
  size_t script_len = 0, count = 0;
  if (!gz_hex_decode(arg, strlen(arg), script, sizeof script, &script_len) || script_len == 0) {
    fprintf(stderr, "gz-chain: the script must be lowercase hex\n");
    return 2;
  }
  gz_chain_result r = gz_chain_script_outputs(&a->multi, script, script_len, outs, MAX_OUTPUTS, &count);
  print_report(a);
  int rc = verdict_line(r);
  if (r == GZ_CHAIN_OK) {
    unsigned long long total = 0;
    for (size_t i = 0; i < count; i++) {
      printf("  ");
      print_output(&outs[i]);
      printf("\n");
      total += outs[i].value;
    }
    printf("outputs: %zu unspent, %llu sat in total\n", count, total);
  }
  return rc;
}

static int cmd_outspend(app *a, const char *arg_txid, const char *arg_vout) {
  uint8_t txid[GZ_HASH_LEN];
  gz_outspend o;
  char *end = NULL;
  if (!parse_txid(arg_txid, txid)) return 2;
  unsigned long vout = strtoul(arg_vout, &end, 10);
  if (*arg_vout == '\0' || *arg_vout == '-' || end == NULL || *end != '\0' || vout > 0xfffffffful) {
    fprintf(stderr, "gz-chain: the output index must be a number\n");
    return 2;
  }
  gz_chain_result r = gz_chain_outspend(&a->multi, txid, (uint32_t)vout, &o);
  print_report(a);
  int rc = verdict_line(r);
  if (r == GZ_CHAIN_OK) {
    printf("output: ");
    print_outspend(&o);
    printf("\n");
  }
  return rc;
}

static void print_confirmation(gz_chain_result r, const gz_confirmation *c) {
  if (r == GZ_CHAIN_OK) {
    print_tx_status(&c->status);
    if (c->status.state == GZ_TX_CONFIRMED)
      printf("; proof of %lu step(s) at position %lu checks against the header",
             (unsigned long)c->proof.depth, (unsigned long)c->proof.pos);
  } else {
    printf("%s", gz_chain_result_name(r));
  }
  printf("\n");
}

static int cmd_proof(app *a, const char *arg) {
  uint8_t txid[GZ_HASH_LEN];
  gz_confirmation conf;
  if (!parse_txid(arg, txid)) return 2;
  /* each server on its own first, so a server whose proof fails is named */
  for (size_t i = 0; i < a->n; i++) {
    gz_chain_result r = gz_chain_confirm_tx(&a->servers[i], a->network, txid, &conf);
    printf("  %s\n    ", a->urls[i]);
    print_confirmation(r, &conf);
  }
  gz_chain_result r = gz_chain_confirm_tx(&a->multi, a->network, txid, &conf);
  int rc = verdict_line(r);
  if (r == GZ_CHAIN_OK) {
    printf("transaction: ");
    print_confirmation(r, &conf);
    if (conf.status.state != GZ_TX_CONFIRMED) return 1;
    if (a->network == GZ_NET_SIGNET) {
      printf("note: on signet a block is authorised by a signature this tool does not check;\n"
             "      agreement between independent servers is what backs this answer\n");
    } else {
      printf("note: the header's proof of work was checked against its own target only\n");
    }
  }
  return rc;
}

static int cmd_fee(app *a) {
  gz_fee_estimates f;
  gz_chain_result r = gz_chain_fee_estimates(&a->multi, &f);
  print_report(a);
  int rc = verdict_line(r);
  if (r == GZ_CHAIN_OK) {
    printf("fee estimates, target:sat/vB, highest of the servers: ");
    print_fees(&f);
    printf("\n");
  }
  return rc;
}

static int cmd_broadcast(app *a, const char *arg) {
  static uint8_t raw[MAX_TX_BYTES];
  uint8_t txid[GZ_HASH_LEN];
  size_t len = 0;
  gz_broadcast_result br;
  if (!gz_hex_decode(arg, strlen(arg), raw, sizeof raw, &len) || !gz_txid_from_raw(raw, len, txid)) {
    fprintf(stderr, "gz-chain: that is not a serialized transaction in lowercase hex\n");
    return 2;
  }
  gz_chain_result r = gz_chain_broadcast(&a->multi, raw, len, &br);
  print_report(a);
  printf("verdict: %s\n", gz_chain_result_name(r));
  if (r == GZ_CHAIN_OK) {
    printf("broadcast: accepted by at least one server, txid ");
    print_hash(br.txid);
    printf("\n");
    return 0;
  }
  if (r == GZ_CHAIN_REJECTED) printf("broadcast: refused: %s\n", br.reason);
  return 1;
}

int main(int argc, char **argv) {
  app a;
  const char *args[4];
  int n_args = 0;
  memset(&a, 0, sizeof a);
  a.network = GZ_NET_SIGNET;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      usage(stdout);
      return 0;
    } else if (strcmp(argv[i], "--network") == 0) {
      if (++i >= argc || !gz_network_from_name(argv[i], &a.network)) {
        fprintf(stderr, "gz-chain: --network takes signet, testnet4, testnet or mainnet\n");
        return 2;
      }
    } else if (strcmp(argv[i], "--server") == 0) {
      if (++i >= argc) {
        fprintf(stderr, "gz-chain: --server takes an address\n");
        return 2;
      }
      if (a.n >= GZ_MULTI_MAX_SERVERS) {
        fprintf(stderr, "gz-chain: at most %d servers\n", GZ_MULTI_MAX_SERVERS);
        return 2;
      }
      a.urls[a.n++] = argv[i];
    } else if (argv[i][0] == '-' && argv[i][1] == '-') {
      fprintf(stderr, "gz-chain: unknown option %s\n", argv[i]);
      return 2;
    } else if (n_args < 4) {
      args[n_args++] = argv[i];
    } else {
      usage(stderr);
      return 2;
    }
  }
  if (n_args == 0) {
    usage(stderr);
    return 2;
  }
  const char *cmd = args[0];
  int want = -1;
  if (strcmp(cmd, "tip") == 0 || strcmp(cmd, "fee") == 0) want = 1;
  if (strcmp(cmd, "tx") == 0 || strcmp(cmd, "script") == 0 || strcmp(cmd, "proof") == 0 ||
      strcmp(cmd, "broadcast") == 0)
    want = 2;
  if (strcmp(cmd, "outspend") == 0) want = 3;
  if (want < 0 || n_args != want) {
    usage(stderr);
    return 2;
  }
  /* Decided before anything touches the network. */
  if (strcmp(cmd, "broadcast") == 0 && a.network == GZ_NET_MAINNET) {
    fprintf(stderr, "gz-chain: refusing to broadcast on mainnet\n");
    return 2;
  }

  if (a.n == 0) {
    const char *const *d = default_servers(a.network);
    while (d[a.n] != NULL && a.n < GZ_MULTI_MAX_SERVERS) {
      a.urls[a.n] = d[a.n];
      a.n++;
    }
  }
  if (!gz_http_curl_create(&a.http, false)) {
    fprintf(stderr, "gz-chain: cannot start the HTTPS client\n");
    return 1;
  }
  int rc = 1;
  size_t made = 0;
  for (; made < a.n; made++) {
    gz_esplora_config cfg;
    gz_esplora_config_default(&cfg);
    cfg.base_url = a.urls[made];
    if (strncmp(a.urls[made], "https://", 8) != 0 ||
        gz_esplora_create(&cfg, &a.http, &a.servers[made]) != GZ_CHAIN_OK) {
      fprintf(stderr, "gz-chain: not a usable https server address: %s\n", a.urls[made]);
      rc = 2;
      goto out;
    }
  }
  gz_multi_config mc;
  gz_multi_config_default(&mc);
  mc.max_outputs = MAX_OUTPUTS;
  if (gz_multi_create(&mc, a.servers, a.n, &a.multi) != GZ_CHAIN_OK) {
    fprintf(stderr, "gz-chain: cannot set up the comparison\n");
    goto out;
  }
  printf("network: %s, %zu server(s)\n", gz_network_name(a.network), a.n);
  if (a.n < 2)
    printf("warning: one server cannot be compared with anything; no answer will be confirmed\n");

  if (strcmp(cmd, "tip") == 0) rc = cmd_tip(&a);
  else if (strcmp(cmd, "tx") == 0) rc = cmd_tx(&a, args[1]);
  else if (strcmp(cmd, "script") == 0) rc = cmd_script(&a, args[1]);
  else if (strcmp(cmd, "outspend") == 0) rc = cmd_outspend(&a, args[1], args[2]);
  else if (strcmp(cmd, "proof") == 0) rc = cmd_proof(&a, args[1]);
  else if (strcmp(cmd, "fee") == 0) rc = cmd_fee(&a);
  else rc = cmd_broadcast(&a, args[1]);

out:
  gz_chain_destroy(&a.multi);
  for (size_t i = 0; i < made; i++) gz_chain_destroy(&a.servers[i]);
  gz_http_curl_destroy(&a.http);
  return rc;
}
