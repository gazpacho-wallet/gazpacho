/* SPDX-License-Identifier: MIT */
#include "gzp.h"
#include "notify.h"

static void emit_line(void *ctx, uint32_t code, const uint8_t *bytes, size_t len)
{
    (void)ctx;
    (void)bytes;
    /* The bytes are not printed: a NOTIFY may one day carry something the
     * user should see only in the interface. */
    gzp_log("notify code=%u len=%zu", (unsigned)code, len);
}

void gzp_notify_lines(gzp_notify_sink_t *s)
{
    s->emit = emit_line;
    s->ctx = 0;
}
