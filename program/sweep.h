/* SPDX-License-Identifier: MIT */
/* The host's timeout sweep of a factory, test build only (--test-sweep):
 * docs/notes/integration.md, the signet run's recovery; spec/exit.md 3.2 and
 * rule H15 (INTERIM, Slice 1). Reads the journal of a host's folder (best a
 * copy: opening a journal can write), rebuilds each funded round's signed
 * tree from the round's proposal and the host's final signatures, prints the
 * signed tree (the root kickoff first) and the host's timeout spends of the
 * root kickoff's outputs, signed with the host's key, to `to_script`, at
 * `feerate` sat/kvB. Refuses an output with an owed member below it
 * (`owed_member`, 1-based in tree order; Slice 1 owes none, so the tests set
 * it) and one whose timeout height is above `height` (printed as refused;
 * with `force` it is built anyway, for a test that shows the node refuses it
 * too). Never broadcasts. Lines:
 *   sweep-round id=.. members=N nodes=K end=E funding=TXID:V amount=A finals=F
 *   sweep-tree node=I parent=P vout=V kind=K depth=D first=F count=C cltv=L txid=T vsize=S tx=HEX
 *   sweep-refused node=I vout=V why=owed member=M | why=not-yet locktime=L height=H
 *   sweep-spend node=I vout=V amount=A fee=F out=O locktime=L vsize=S tx=HEX
 *   sweep-error why=..  |  sweep-none why=no-signed-round */
#ifndef GZP_SWEEP_H
#define GZP_SWEEP_H

#include <stddef.h>
#include <stdint.h>
#include <secp256k1.h>

struct gzp_wallet;
#include "keys.h"

typedef struct {
    const char *dir;
    struct gzp_wallet *wallet;
    const gzp_keys_t *keys;
    secp256k1_context *secp;
    uint32_t height;
    int force;
    int owed_member;
    const uint8_t *to_script;
    size_t to_len;
    uint64_t feerate;
} gzp_sweep_in_t;

int gzp_sweep_run(const gzp_sweep_in_t *in);

/* --test-spend-coin TXID:VOUT:AMOUNT:SCRIPT (test build): one coin of this
 * wallet (found among its first 300 receive and change outputs by the script
 * it pays) spent whole, by key path, to `to_script` at `feerate` sat/kvB.
 * Prints "spend-coin change=C index=I amount=A" and "spend-tx ... tx=HEX", or
 * spend-refused / spend-error. Broadcasts it only when `send` is given
 * (--test-never-fund, faults.h): then "spend-coin-broadcast ..." too. */
#include "pchain.h"
#include "unlock.h"
#include "gazpacho/wallet_keys.h"
typedef struct {
    const gzp_unlock_t *unlock;
    secp256k1_context *secp;
    gzw_network wnet;
    const char *spec;
    const uint8_t *to_script;
    size_t to_len;
    uint64_t feerate;
    gzp_chain_t *send;    /* broadcast the spend through this chain (test build, --test-never-fund), or NULL */
} gzp_spend_in_t;

int gzp_spend_coin(const gzp_spend_in_t *in);

#endif
