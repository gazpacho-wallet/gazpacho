/* SPDX-License-Identifier: MIT */
/* The host's funding fault switches, test build only (Slice 1.5 plan, P6;
 * docs/notes/integration.md). Each one makes the host misbehave in one way
 * that a member must survive, for the S tests on the local test chain:
 *
 *   --test-never-fund   the funding is never broadcast (S5), nor any
 *                       spend-back of its inputs: the inputs are spent only
 *                       by the test (--test-spend-coin, which with this
 *                       switch also broadcasts its spend).
 *
 * The funding is known by its txid: a plan the wallet port signed (the
 * engine broadcasts what sign_plan gave it, at once). A spend-back is a
 * broadcast that spends an input of such a funding. Everything else the
 * node broadcasts goes out as usual. None of this is in the release build. */
#ifndef GZP_FAULTS_H
#define GZP_FAULTS_H

#ifdef GZP_TEST_BUILD
#include <stddef.h>
#include <stdint.h>

#include "gazpacho/funding.h"
#include "gzp.h"
#include "pchain.h"

/* The wallet port the node is given: `real`, or one that notes every txid
 * sign_plan returns, when a switch needs to know the fundings. Kept for the
 * whole run (the in-process restarts too). */
const gz_wallet_port_t *gzp_fault_port(const gzp_options_t *o, const gz_wallet_port_t *real);
/* A BROADCAST action: 1 if a switch took it (it is not sent), 0 to send it as
 * usual. */
int gzp_fault_broadcast(gzp_chain_t *c, const gzp_options_t *o, const uint8_t *tx, size_t len);
/* Sends `tx` now, through the loop thread's own client (pchain.h, lookup),
 * and writes the outcome: "LABEL-broadcast txid=.. outcome=accepted|refused
 * reason=..". 1 accepted, 0 refused, -1 not sent (no chain, mainnet, not a
 * transaction, no answer). */
int gzp_fault_send_now(gzp_chain_t *c, const char *label, const uint8_t *tx, size_t len);
#endif

#endif
