/* SPDX-License-Identifier: MIT */
/* The program's command line: mainnet refused before anything else, the
 * member's host address in the messages.md section 2 form, the roles and
 * the interface options. */
#include <stdio.h>
#include <string.h>

#include "gzp.h"

static int failures;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); failures++; } } while (0)

#define KEY "02" "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

static int parse(gzp_options_t *o, const char *const *args)
{
    char *argv[32];
    int argc = 0;
    argv[argc++] = (char *)"gazpacho";
    while (*args && argc < 31) argv[argc++] = (char *)*args++;
    argv[argc] = NULL;
    return gzp_options_parse(o, argc, argv);
}

int main(void)
{
    gzp_options_t o;
    {
        const char *a[] = {"--network", "mainnet", NULL};
        CHECK(parse(&o, a) == GZP_EXIT_USAGE); /* refused even without a data folder */
    }
    {
        const char *a[] = {"--data-dir", "d", "--role", "host", "--no-chain", "--network", "mainnet", NULL};
        CHECK(parse(&o, a) == GZP_EXIT_USAGE);
    }
    {
        const char *a[] = {"--data-dir", "d", "--role", "host", "--no-chain", "--network", "regtest", NULL};
        CHECK(parse(&o, a) == GZP_EXIT_USAGE);
    }
    {
        const char *a[] = {"--data-dir", "d", "--role", "host", "--no-chain", NULL};
        CHECK(parse(&o, a) == 0 && o.role == GZP_ROLE_HOST && !strcmp(o.network, "signet") &&
              o.listen_port == 9736 && !strcmp(o.name, "host"));
    }
    {
        const char *a[] = {"--data-dir", "d", "--role", "host", NULL}; /* no chain choice */
        CHECK(parse(&o, a) == GZP_EXIT_USAGE);
    }
    {
        const char *a[] = {"--data-dir", "d", "--role", "member", "--no-chain", NULL}; /* no host */
        CHECK(parse(&o, a) == GZP_EXIT_USAGE);
    }
    {
        const char *a[] = {"--data-dir", "d", "--role", "member", "--no-chain", "--connect",
                           KEY "@127.0.0.1:9736", "--interface-port", "40000", NULL};
        CHECK(parse(&o, a) == 0 && o.role == GZP_ROLE_MEMBER && o.have_connect && o.connect_key[0] == 2 &&
              o.connect_key[32] == 0x98 && !strcmp(o.connect_host, "127.0.0.1") && o.connect_port == 9736 &&
              o.interface_port == 40000);
    }
    {
        const char *a[] = {"--data-dir", "d", "--role", "member", "--no-chain", "--connect",
                           KEY "@[::1]:9736", NULL};
        CHECK(parse(&o, a) == 0 && !strcmp(o.connect_host, "::1"));
    }
    {
        const char *a[] = {"--data-dir", "d", "--role", "member", "--no-chain", "--connect", "02ab@127.0.0.1:1", NULL};
        CHECK(parse(&o, a) == GZP_EXIT_USAGE); /* short key */
    }
    {
        const char *a[] = {"--data-dir", "d", "--role", "host", "--no-chain", "--no-interface",
                           "--interface-port", "1", NULL};
        CHECK(parse(&o, a) == GZP_EXIT_USAGE);
    }
    {
        const char *a[] = {"--data-dir", "d", "--role", "host", "--no-chain", "--listen", "127.0.0.1:0",
                           "--no-interface", "--name", "h1", NULL};
        CHECK(parse(&o, a) == 0 && o.listen_port == 0 && o.no_interface && !strcmp(o.name, "h1"));
    }
    {
        const char *a[] = {"--data-dir", "d", "--role", "watcher", "--no-chain", NULL};
        CHECK(parse(&o, a) == GZP_EXIT_USAGE);
    }
    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    printf("options: all checks passed\n");
    return 0;
}
