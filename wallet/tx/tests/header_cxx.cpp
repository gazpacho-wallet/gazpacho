// The library header must be usable from C++11 (strict, -pedantic-errors):
// the network constants in particular, which are compound literals in C.
#include "gazpacho/wallet_tx.h"

static gzt_network pick(int i) {
    return i == 0 ? GZT_NET_SIGNET : i == 1 ? GZT_NET_TESTNET3 : i == 2 ? GZT_NET_TESTNET4
                                                                       : GZT_NET_REGTEST;
}

int main() {
    gzt_funding_request req = {};
    req.net = GZT_NET_SIGNET;
    gzt_feerate r = {GZT_FEERATE_TEST_DEFAULT_SAT_PER_KVB};
    return gzt_network_eq(req.net, pick(0)) && r.sat_per_kvb == 100 ? 0 : 1;
}
