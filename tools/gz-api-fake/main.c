/* SPDX-License-Identifier: MIT */
/* gz-api-fake: TEST ONLY. Serves the local API (spec/local-api.md draft 4)
 * on 127.0.0.1 with the fake backend, for building the interface (stream S10)
 * before the program exists. It is not a wallet: the fake's passphrase check
 * is a plain comparison, its words are a fixed test phrase, and nothing is
 * written but the API's own files (the first-run redirect file, the attempts
 * file, the socket token) in the data folder given.
 *
 *   gz-api-fake --data-dir DIR [--port N] [--locked] [--no-ipv6]
 *               [--tunnel-port N] [--quiet]
 *
 * --locked starts with a wallet whose passphrase is the fixture in
 * ports/api/fake/fake_backend.h; without it the program starts at first run
 * and prints the path of the redirect file to open. --port 0 picks a free
 * port. The first line printed is always "listening http://127.0.0.1:PORT/". */
#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "fake_backend.h"

static gz_api_server *g_srv;

static void on_signal(int sig)
{
    (void)sig;
    if (g_srv) gz_api_server_stop(g_srv);
}

static void log_line(void *ctx, const char *line)
{
    if (ctx) return;                                    /* --quiet */
    fprintf(stderr, "%s\n", line);
}

static char g_first_run[700];

static void first_run(void *ctx, const char *path)
{
    (void)ctx;
    /* the path only: the token is inside the owner-only file (4.3) */
    snprintf(g_first_run, sizeof g_first_run, "%s", path);
}

int main(int argc, char **argv)
{
    gz_api_config cfg;
    gz_fake fake;
    const char *err = NULL;
    int i, locked = 0, quiet = 0, rc;
    struct sigaction sa;
    memset(&cfg, 0, sizeof cfg);
    cfg.port = 39735;
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--data-dir") == 0 && i + 1 < argc) cfg.data_dir = argv[++i];
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) cfg.port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--tunnel-port") == 0 && i + 1 < argc) cfg.tunnel_port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--locked") == 0) locked = 1;
        else if (strcmp(argv[i], "--no-ipv6") == 0) cfg.no_ipv6 = 1;
        else if (strcmp(argv[i], "--quiet") == 0) quiet = 1;
        else {
            fprintf(stderr, "usage: gz-api-fake --data-dir DIR [--port N] [--locked] [--no-ipv6] [--tunnel-port N] [--quiet]\n");
            return 2;
        }
    }
    if (!cfg.data_dir) {
        fprintf(stderr, "gz-api-fake: --data-dir is required\n");
        return 2;
    }
    fprintf(stderr, "gz-api-fake: TEST BACKEND. This is not a wallet; never use it with real coins.\n");
    gz_fake_init(&fake, locked ? GZ_FAKE_LOCKED : GZ_FAKE_FIRST_RUN);
    cfg.backend = &gz_fake_backend;
    cfg.backend_ctx = &fake;
    cfg.log = log_line;
    cfg.on_first_run_file = first_run;
    cfg.ctx = quiet ? (void *)&fake : NULL;
    g_srv = gz_api_server_new(&cfg, &err);
    if (!g_srv) {
        fprintf(stderr, "gz-api-fake: %s\n", err ? err : "cannot start");
        gz_fake_free(&fake);
        return 1;
    }
    fake.srv = g_srv;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    printf("listening http://127.0.0.1:%u/\n", (unsigned)gz_api_server_port(g_srv));
    printf("local socket %s\n", gz_api_server_socket_path(g_srv));
    if (g_first_run[0]) printf("first run: open file://%s in a browser\n", g_first_run);
    fflush(stdout);
    rc = gz_api_server_run(g_srv);
    gz_api_server_free(g_srv);
    g_srv = NULL;
    gz_fake_free(&fake);
    return rc ? 1 : 0;
}
