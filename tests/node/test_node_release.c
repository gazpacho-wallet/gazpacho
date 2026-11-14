/* The release node (gazpacho_node, no GZ_TEST_KINDS): no test engine, so a
 * test-engine count is refused, kind 32767 is just a kind no engine takes,
 * and test commands are unknown. The node part works as in the test build. */
#include "node_test.h"

int main(void)
{
    h_t h;
    gz_node_config_t cfg;
    gz_ports_t ports;
    memset(&cfg, 0, sizeof cfg);
    memset(&ports, 0, sizeof ports);
    h_init(&h, 1, 0);
    ports.random.fill = h_fill;
    ports.clock.now_ms = h_now;
    cfg.test_engines = 1;
    CHECK(gz_node_init(h.n, &ports, &cfg, 1) == GZ_ERR_ARGUMENT);
    h_new_node(&h);
    CHECK(h_start(&h) == GZ_OK);
    CHECK(h_records_of(&h, GZ_RECORD_KEY_EPOCH) == 0); /* the start saves nothing */
    gz_link_t l = h_host_link(1);
    h_peer(&h, &l, 1, 0);
    size_t m = h_mark(&h);
    h_test_msg(&h, &l, "GZPI", (const uint8_t *)"x", 1, 0x7e57);
    CHECK(h_said(&h, m, "drop why=kind kind=32767") && h_count(&h, m, GZ_ACTION_SAVE) == 0);
    m = h_mark(&h);
    h_cmd(&h, GZ_TE_CMD_SLOT_OPEN, NULL, 0);
    h_cmd(&h, GZ_TE_CMD_TIMER, NULL, 0);
    CHECK(h_count(&h, m, GZ_ACTION_NOTIFY) == 2 && h_said(&h, m, "result 404 unknown_command"));
    uint8_t s[32];
    memset(s, 4, sizeof s);
    m = h_mark(&h);
    h_msg(&h, &l, GZ_MSG_KIND_HELLO, s, NULL, 0);
    CHECK(h_count(&h, m, GZ_ACTION_SEND) == 1); /* lobby state 0 for an unknown scope */
    h.restored = 1;
    m = h_mark(&h);
    CHECK(h_restart(&h) == GZ_OK && h.log[m].n_records == 3);
    CHECK_NO_NODE_ERROR(&h);
    h_free(&h);
    return check_done();
}
