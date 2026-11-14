/* libFuzzer target: hostile events from the input's bytes, as host or member
 * (first byte), with one or two test engines. Any status but GZ_OK, from
 * gz_node_start or gz_node_handle, aborts: peers, the chain and the person
 * never cause a node error (node.h). */
#include "hostile.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    h_t h;
    src_t s = {data, size, 0, 0x2545f4914f6cdd1dull};
    if (size < 2) return check_done() * 0; /* (check.h's, used once) */
    h_init(&h, data[0] & 1, 1 + ((data[0] >> 1) & 1));
    s.at = 1;
    if (h_start(&h) != GZ_OK) abort();
    /* Every input byte drives events; a few more after it runs out. */
    for (unsigned e = 0; s.at < s.n && e < 400; e++)
        if (hostile_step(&h, &s) != GZ_OK || gz_node_error_area(h.n) != 0) abort();
    h_free(&h);
    return 0;
}
