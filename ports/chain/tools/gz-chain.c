/*
 * gz-chain: ask chain servers by hand and see each server's answer next to
 * the combined verdict. For manual use and for the walkthroughs.
 *
 *   gz-chain [--network NET] [--server URL]... [--confirmations N] COMMAND [ARGS]
 *
 * Exit status: 0 the command produced an answer that servers of at least two
 * operators gave alike (for `proof`: and the transaction is confirmed and
 * every check passed; for `broadcast`: a server took the transaction);
 * 1 no such answer; 2 bad usage or a refused request.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "gazpacho/chain.h"
#include "gazpacho/chain_esplora.h"
#include "gazpacho/chain_http.h"
#include "gazpacho/chain_multi.h"

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
    case GZ_NET_INVALID: break;
  }
  return DEFAULT_SIGNET;
}

static void usage(FILE *to) {
  fprintf(to,
          "usage: gz-chain [--network signet|testnet4|testnet|mainnet] [--server URL]...\n"
          "                [--confirmations N] COMMAND\n"
          "\n"
          "commands:\n"
          "  tip                    best block height and hash\n"
          "  tx TXID                what the servers claim about a transaction (unchecked)\n"
          "  script HEX             unspent outputs paying this scriptPubKey\n"
          "  outspend TXID VOUT     is this output spent, and by what\n"
          "  proof TXID             check a confirmation: transaction, header, Merkle proof,\n"
          "                         coinbase, and N linked headers (default 6)\n"
          "  fee                    the servers' fee estimates and the rate that would be used\n"
          "  broadcast HEX          send a transaction (refused on mainnet)\n"
          "\n"
          "The network defaults to signet. Without --server, the servers listed in\n"
          "docs/CHAIN-SERVERS.md for the network are used. Addresses must be https, except\n"
          "http for a server on this machine (localhost, 127.0.0.1, [::1]).\n"
          "\n"
          "What the verdict means: every server is first checked to be on the network\n"
          "named. For tip, tx, script, outspend and proof, an answer is given only when\n"
          "servers of at least two different operators give it and none contradicts it\n"
          "about confirmed data. That shows the servers say the same thing; it does not\n"
          "show they are right. Fee estimates are opinions and are never an agreed fact.\n"
          "A broadcast succeeds when any one server takes the transaction.\n");
}

typedef struct app {
  gz_network network;
  uint32_t want_confirmations;
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

/* Prints the verdict line and returns the exit status for it. */
static int verdict_line(const app *a, gz_chain_result r) {
  const gz_multi_report *rep = gz_multi_last_report(&a->multi);
  printf("verdict: %s", gz_chain_result_name(r));
  switch (r) {
    case GZ_CHAIN_OK:
      printf(" (servers of %zu operators give this answer)\n", rep ? rep->operator_count : 0);
      if (rep != NULL && rep->unconfirmed_differs)
        printf("note: the servers differ about unconfirmed data; only what all report is shown\n");
      return 0;
    case GZ_CHAIN_NOT_FOUND: printf(" (the servers all say it does not exist)\n"); return 1;
    case GZ_CHAIN_DISAGREE: printf(" (the servers contradict each other: NOT confirmed)\n"); return 1;
    case GZ_CHAIN_LAG:
      printf(" (one server is a block behind: no answer yet, ask again)\n");
      return 1;
    case GZ_CHAIN_NO_QUORUM:
      printf(" (fewer than two operators answered: cannot confirm)\n");
      return 1;
    default: printf("\n"); return 1;
  }
}

static void print_tx_status(const gz_tx_status *s) {
  switch (s->state) {
    case GZ_TX_UNKNOWN:
      printf(s->unconfirmed_differs ? "not confirmed (in some mempools, not all)"
                                    : "unknown to the server");
      break;
    case GZ_TX_MEMPOOL: printf("in the mempool, unconfirmed"); break;
    case GZ_TX_CONFIRMED:
      printf("confirmed at height %lu in block ", (unsigned long)s->height);
      print_hash(s->block_hash);
      printf("; claims %lu confirmations (tip %lu), unchecked",
             (unsigned long)s->claimed_confirmations, (unsigned long)s->tip_height);
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
    printf(o->unconfirmed_differs ? "no confirmed spend (the servers differ about an unconfirmed one)"
                                  : "not spent");
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
    printf("  %s  [operator: %s]\n    ", a->urls[i], rep->operators[i]);
    if (rep->call == GZ_CALL_BROADCAST) {
      const gz_broadcast_result *b = &ans->u.broadcast;
      if (ans->result == GZ_CHAIN_OK) {
        printf(b->already_known ? "already has it: " : "accepted ");
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
  int rc = verdict_line(a, r);
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
  int rc = verdict_line(a, r);
  if (r == GZ_CHAIN_OK) {
    printf("transaction: ");
    print_tx_status(&st);
    printf("\n");
    if (st.state == GZ_TX_CONFIRMED)
      printf("note: this is what the servers claim; `gz-chain proof` checks it\n");
  }
  return rc;
}

static int cmd_script(app *a, const char *arg) {
  static uint8_t script[GZ_SCRIPT_MAX_LEN];
  static gz_chain_output outs[MAX_OUTPUTS];
  size_t script_len = 0, count = 0;
  bool differs = false;
  if (!gz_hex_decode(arg, strlen(arg), script, sizeof script, &script_len) || script_len == 0) {
    fprintf(stderr, "gz-chain: the script must be lowercase hex\n");
    return 2;
  }
  gz_chain_result r =
      gz_chain_script_outputs(&a->multi, script, script_len, outs, MAX_OUTPUTS, &count, &differs);
  print_report(a);
  int rc = verdict_line(a, r);
  if (r == GZ_CHAIN_OK) {
    unsigned long long total = 0;
    for (size_t i = 0; i < count; i++) {
      printf("  ");
      print_output(&outs[i]);
      printf("\n");
      total += outs[i].value;
    }
    printf("outputs: %zu unspent, %llu sat in total%s\n", count, total,
           differs ? " (unconfirmed outputs not reported by every server are left out)" : "");
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
  int rc = verdict_line(a, r);
  if (r == GZ_CHAIN_OK) {
    printf("output: ");
    print_outspend(&o);
    printf("\n");
  }
  return rc;
}

static void print_confirmation(gz_chain_result r, const gz_confirmation *c) {
  if (r != GZ_CHAIN_OK) {
    printf("%s\n", gz_chain_result_name(r));
    return;
  }
  if (c->status.state != GZ_TX_CONFIRMED) {
    print_tx_status(&c->status);
    printf("\n");
    return;
  }
  printf("confirmed at height %lu in block ", (unsigned long)c->status.height);
  print_hash(c->status.block_hash);
  printf("\n    position %lu of %lu transactions, proof of %lu step(s) checks against the header,\n"
         "    coinbase proof has the same depth, %lu confirmation(s) checked by linked headers\n",
         (unsigned long)c->proof.pos, (unsigned long)c->block.tx_count,
         (unsigned long)c->proof.depth, (unsigned long)c->checked_confirmations);
}

static int cmd_proof(app *a, const char *arg) {
  uint8_t txid[GZ_HASH_LEN];
  gz_confirmation conf;
  if (!parse_txid(arg, txid)) return 2;
  /* each server on its own first, so a server whose proof fails is named */
  for (size_t i = 0; i < a->n; i++) {
    gz_chain_result r =
        gz_chain_confirm_tx(&a->servers[i], a->network, txid, a->want_confirmations, &conf);
    printf("  %s\n    ", a->urls[i]);
    print_confirmation(r, &conf);
  }
  gz_chain_result r = gz_chain_confirm_tx(&a->multi, a->network, txid, a->want_confirmations, &conf);
  int rc = verdict_line(a, r);
  if (r != GZ_CHAIN_OK) return rc;
  printf("transaction: ");
  print_confirmation(r, &conf);
  if (conf.status.state != GZ_TX_CONFIRMED) return 1; /* nothing was proved */
  if (conf.checked_confirmations < a->want_confirmations)
    printf("note: %lu confirmations were asked for; the chain is only %lu deep above it\n",
           (unsigned long)a->want_confirmations, (unsigned long)conf.checked_confirmations);
  if (a->network == GZ_NET_SIGNET) {
    printf("note: on signet a block is authorised by a signature this tool does not check;\n"
           "      the headers prove no work. Servers of different operators giving the same\n"
           "      answers is all that backs this result.\n");
  } else {
    printf("note: each header's proof of work was checked against its own stated target;\n"
           "      whether that target is the one the network required was not checked\n");
  }
  return 0;
}

static int cmd_fee(app *a) {
  gz_fee_estimates f;
  gz_fee_choice choice;
  gz_chain_result r = gz_chain_fee_estimates(&a->multi, &f);
  print_report(a);
  printf("verdict: %s", gz_chain_result_name(r));
  if (r == GZ_CHAIN_OK) {
    printf(" (estimates are opinions, not agreed facts)\n");
    printf("lowest estimate per target, sat/vB, cut at the ceiling: ");
    print_fees(&f);
    printf("\n");
  } else if (r == GZ_CHAIN_DISAGREE) {
    printf(" (the servers' estimates are too far apart to combine)\n");
  } else {
    printf("\n");
  }
  /* the rate the software would actually use for a 6-block target */
  gz_chain_result rr = gz_chain_choose_fee_rate(&a->multi, a->network, 6, 200000, &choice);
  if (rr == GZ_CHAIN_OK) {
    printf("rate that would be used (target 6 blocks, ceiling 200 sat/vB): %llu.%03llu sat/vB, %s\n",
           (unsigned long long)(choice.sat_per_kvb / 1000),
           (unsigned long long)(choice.sat_per_kvb % 1000),
           choice.source == GZ_FEE_FROM_TEST_DEFAULT
               ? "the fixed test-network rate; the estimates above are not used"
               : "from the estimates above");
  } else {
    printf("rate that would be used: none (%s)\n", gz_chain_result_name(rr));
  }
  return r == GZ_CHAIN_OK ? 0 : 1;
}

static int cmd_broadcast(app *a, const char *arg) {
  uint8_t txid[GZ_HASH_LEN];
  size_t len = 0;
  gz_broadcast_result br;
  uint8_t *raw = malloc(GZ_TX_MAX_BYTES);
  if (raw == NULL) return 1;
  if (!gz_hex_decode(arg, strlen(arg), raw, GZ_TX_MAX_BYTES, &len) ||
      !gz_txid_from_raw(raw, len, txid)) {
    fprintf(stderr, "gz-chain: that is not a serialized transaction in lowercase hex\n");
    free(raw);
    return 2;
  }
  /* The refusal does not rest on the --network flag alone: no server that
   * turns out to be on mainnet is sent anything, whatever the flag says. */
  for (size_t i = 0; i < a->n; i++) {
    gz_network found = GZ_NET_INVALID;
    if (gz_chain_identify_network(&a->servers[i], &found) == GZ_CHAIN_OK &&
        found == GZ_NET_MAINNET) {
      fprintf(stderr, "gz-chain: refusing to broadcast: %s is a mainnet server\n", a->urls[i]);
      free(raw);
      return 2;
    }
  }
  gz_chain_result r = gz_chain_broadcast(&a->multi, raw, len, &br);
  free(raw);
  print_report(a);
  printf("verdict: %s\n", gz_chain_result_name(r));
  if (r == GZ_CHAIN_OK) {
    printf("broadcast: %s, txid ", br.already_known ? "a server already had it"
                                                   : "taken by at least one server");
    print_hash(br.txid);
    printf("\nnote: taken is not relayed; check with `gz-chain tx` that it appears\n");
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
  a.want_confirmations = 6;

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
      usage(stdout);
      return 0;
    } else if (strcmp(argv[i], "--network") == 0) {
      if (++i >= argc || !gz_network_from_name(argv[i], &a.network)) {
        fprintf(stderr, "gz-chain: --network takes signet, testnet4, testnet or mainnet\n");
        return 2;
      }
    } else if (strcmp(argv[i], "--confirmations") == 0) {
      char *end = NULL;
      unsigned long v = ++i < argc ? strtoul(argv[i], &end, 10) : 0;
      if (i >= argc || end == NULL || *end != '\0' || v < 1 || v > GZ_CONFIRM_MAX_DEPTH) {
        fprintf(stderr, "gz-chain: --confirmations takes a number from 1 to %d\n",
                GZ_CONFIRM_MAX_DEPTH);
        return 2;
      }
      a.want_confirmations = (uint32_t)v;
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
  /* Decided before anything touches the network. The servers themselves are
   * checked as well, in cmd_broadcast. */
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
  if (!gz_http_curl_create(&a.http, NULL)) {
    fprintf(stderr, "gz-chain: cannot start the HTTPS client\n");
    return 1;
  }
  int rc = 1;
  size_t made = 0;
  for (; made < a.n; made++) {
    gz_esplora_config cfg;
    gz_esplora_config_default(&cfg);
    cfg.base_url = a.urls[made];
    if (gz_esplora_create(&cfg, &a.http, &a.servers[made]) != GZ_CHAIN_OK) {
      fprintf(stderr,
              "gz-chain: not a usable server address: %s\n"
              "          (https only; http only for localhost, 127.0.0.1 or [::1])\n",
              a.urls[made]);
      rc = 2;
      goto out;
    }
  }
  gz_multi_config mc;
  gz_multi_config_default(&mc, a.network);
  mc.max_outputs = MAX_OUTPUTS;
  if (gz_multi_create(&mc, a.servers, a.n, &a.multi) != GZ_CHAIN_OK) {
    fprintf(stderr, "gz-chain: the same server or the same host was given more than once;\n"
                    "          a server cannot be compared with itself\n");
    rc = 2;
    goto out;
  }
  size_t operators = gz_multi_operator_count(&a.multi);
  printf("network: %s, %zu server(s) of %zu operator(s)\n", gz_network_name(a.network), a.n,
         operators);
  if (operators < 2)
    printf("warning: fewer than two operators; nothing can be compared and no answer will be "
           "confirmed\n");

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
