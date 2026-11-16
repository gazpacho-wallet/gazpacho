/* A hostile peer never causes a node error (node.h, the engine rule;
 * composite-node.md 8.1): seeded runs of random events from peers, the chain
 * and the user, as host and as member, with one and two test engines, and
 * restarts from storage between them. Every call must return GZ_OK and no
 * node-error may be recorded. Usage: test_node_hostile [runs] [events]. */
#include <stdlib.h>

#include "hostile.h"

int main(int argc, char **argv)
{
    unsigned runs = argc > 1 ? (unsigned)strtoul(argv[1], NULL, 10) : 40;
    unsigned events = argc > 2 ? (unsigned)strtoul(argv[2], NULL, 10) : 1500;
    unsigned errors = 0;
    for (unsigned r = 0; r < runs; r++) {
        h_t h;
        src_t s = {NULL, 0, 0, 0x9e3779b97f4a7c15ull ^ (r + 1) * 0x100000001b3ull};
        h_init(&h, (int)(r & 1), 1 + (r >> 1) % 2);
        if (h_start(&h) != GZ_OK) errors++;
        for (unsigned e = 0; e < events && errors == 0; e++) {
            gz_status_t st = hostile_step(&h, &s);
            if (st != GZ_OK) {
                printf("run %u event %u: status %d, engine 0x%04x\n", r, e, (int)st, gz_node_error_area(h.n));
                errors++;
            }
        }
        CHECK(errors == 0);
        CHECK_NO_NODE_ERROR(&h);
        h_free(&h);
        if (errors) break;
    }
    return check_done();
}
