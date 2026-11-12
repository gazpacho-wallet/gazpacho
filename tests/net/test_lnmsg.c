/* BOLT 1's init, ping, pong, warning and error, as lobby connections use
 * them (messages.md section 2). */
#include <string.h>
#include "../check.h"
#include "hex.h"
#include "lnmsg.h"

static const char *SIGNET_HEX = "f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e9739881" "08000000";
static const char *INIT_HEX = "0010" "0000" "0000" "0120" "f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000";

static uint8_t m[70000];

static gz_ln_err_t init_hex(const char *h)
{
    size_t n = unhex(h, m, sizeof m);
    CHECK(n != (size_t)-1);
    return gz_ln_init_check(m, n, GZ_LN_CHAIN_SIGNET);
}

int main(void)
{
    uint8_t out[70000], other[32];
    size_t n;
    uint16_t v;
    char text[16];
    /* Signet's chain hash, and our init: no features, networks = [signet]. */
    CHECK(unhex(SIGNET_HEX, other, 32) == 32 && memcmp(other, GZ_LN_CHAIN_SIGNET, 32) == 0);
    CHECK(gz_ln_init_write(GZ_LN_CHAIN_SIGNET, out, sizeof out, &n) == 0 && n == 40);
    CHECK(unhex(INIT_HEX, m, sizeof m) == 40 && memcmp(out, m, 40) == 0);
    CHECK(gz_ln_init_write(GZ_LN_CHAIN_SIGNET, out, 39, &n) != 0);
    CHECK(gz_ln_init_check(out, 40, GZ_LN_CHAIN_SIGNET) == GZ_LN_OK);
    /* Another chain; two chains; none; networks missing. */
    memset(other, 0x6f, 32);
    CHECK(gz_ln_init_check(out, 40, other) == GZ_LN_NETWORK);
    CHECK(init_hex("0010000000000140f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000"
                   "6fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000") == GZ_LN_NETWORK);
    CHECK(init_hex("001000000000" "0100") == GZ_LN_NETWORK);
    CHECK(init_hex("001000000000") == GZ_LN_NETWORK);
    CHECK(init_hex("0010000000000121" "f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000ff") == GZ_LN_MALFORMED);
    /* Feature bits: odd ones are fine (449 is factory_capable, odd), an even
     * one is unknown and required, in either field. */
    CHECK(init_hex("0010" "0000" "0001" "02" "0120" "f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000") == GZ_LN_OK);
    CHECK(init_hex("0010" "0000" "0001" "01" "0120" "f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000") == GZ_LN_REQUIRED_FEATURE);
    CHECK(init_hex("0010" "0001" "04" "0000" "0120" "f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000") == GZ_LN_REQUIRED_FEATURE);
    CHECK(init_hex("0010" "0001" "80" "0000" "0120" "f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000") == GZ_LN_OK);
    CHECK(init_hex("0010" "0000" "0002" "4000" "0120" "f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000") == GZ_LN_REQUIRED_FEATURE);
    {
        /* bit 449: byte 56 from the end, bit 1 */
        char h[400] = "0010" "0000" "0039" "02";
        size_t i;
        for (i = 0; i < 56; i++) strcat(h, "00");
        strcat(h, "0120f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000");
        CHECK(init_hex(h) == GZ_LN_OK);
    }
    /* Too short at every field; a feature length past the end; remote_addr
     * (odd) skipped; an unknown even record; records out of order. */
    CHECK(init_hex("0010") == GZ_LN_MALFORMED);
    CHECK(init_hex("001000") == GZ_LN_MALFORMED);
    CHECK(init_hex("00100000") == GZ_LN_MALFORMED);
    CHECK(init_hex("0010000000") == GZ_LN_MALFORMED);
    CHECK(init_hex("00100002ff") == GZ_LN_MALFORMED);
    CHECK(init_hex("00100001ff") == GZ_LN_MALFORMED); /* no room for flen */
    CHECK(init_hex("001000000002ff") == GZ_LN_MALFORMED);
    CHECK(init_hex("0011000000000120f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000") == GZ_LN_MALFORMED);
    CHECK(init_hex("0010000000000120f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000" "0306017f00000126") == GZ_LN_OK);
    CHECK(init_hex("0010000000000120f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000" "0400") == GZ_LN_MALFORMED);
    CHECK(init_hex("0010000000000306017f00000126" "0120f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c4225e973988108000000") == GZ_LN_MALFORMED);
    /* ping: num_pong_bytes read, the ignored bytes must be there; pong. */
    CHECK(gz_ln_ping_write(4, 3, out, sizeof out, &n) == 0 && n == 9);
    CHECK(unhex("0012000400030000 00", m, sizeof m) == 9 && memcmp(out, m, 9) == 0);
    CHECK(gz_ln_ping_read(out, n, &v) == GZ_LN_OK && v == 4);
    CHECK(gz_ln_ping_read(out, n - 1, &v) == GZ_LN_MALFORMED);
    CHECK(gz_ln_ping_read(out, 5, &v) == GZ_LN_MALFORMED);
    CHECK(gz_ln_ping_write(1, 65529, out, sizeof out, &n) == 0 && n == 65535);
    CHECK(gz_ln_ping_write(1, 65530, out, sizeof out, &n) != 0);
    CHECK(gz_ln_ping_write(1, 10, out, 15, &n) != 0);
    CHECK(gz_ln_pong_write(5, out, sizeof out, &n) == 0 && n == 9 && out[1] == 19);
    CHECK(gz_ln_pong_read(out, n, &v) == GZ_LN_OK && v == 5);
    CHECK(gz_ln_pong_read(out, n - 1, &v) == GZ_LN_MALFORMED);
    CHECK(gz_ln_pong_read(out, 3, &v) == GZ_LN_MALFORMED);
    CHECK(gz_ln_pong_write(5, out, 8, &n) != 0);
    out[1] = 18;
    CHECK(gz_ln_pong_read(out, 9, &v) == GZ_LN_MALFORMED);
    CHECK(GZ_LN_PONG_IGNORE_FROM == 65532);
    /* warning and error: zero channel_id, text; reading replaces what is not
     * printable and truncates to the buffer. */
    CHECK(gz_ln_alert_write(GZ_LN_WARNING, "bad kind", out, sizeof out, &n) == 0 && n == 44);
    CHECK(out[0] == 0 && out[1] == 1 && out[34] == 0 && out[35] == 8 && memcmp(out + 36, "bad kind", 8) == 0);
    CHECK(gz_ln_alert_read(out, n, text, sizeof text) == GZ_LN_OK && strcmp(text, "bad kind") == 0);
    CHECK(gz_ln_alert_write(GZ_LN_PING, "x", out, sizeof out, &n) != 0);
    CHECK(gz_ln_alert_write(GZ_LN_ERROR, "a much longer text", out, sizeof out, &n) == 0 && out[1] == 17);
    out[37] = 7;
    CHECK(gz_ln_alert_read(out, n, text, sizeof text) == GZ_LN_OK && strcmp(text, "a?much longer t") == 0);
    CHECK(gz_ln_alert_read(out, n - 1, text, sizeof text) == GZ_LN_MALFORMED);
    CHECK(gz_ln_alert_read(out, 35, text, sizeof text) == GZ_LN_MALFORMED);
    out[1] = 18;
    CHECK(gz_ln_alert_read(out, n, text, sizeof text) == GZ_LN_MALFORMED);
    return check_done();
}
