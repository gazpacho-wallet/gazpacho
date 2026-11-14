/* SPDX-License-Identifier: MIT */
/* Static files, compiled into the program (spec/local-api.md 5.4): no file is
 * read from disk at request time, so there is no path to traverse. The real
 * interface (stream S10) replaces the placeholder page; only exact paths
 * match, and every other path answers 404. */
#include <string.h>

#include "internal.h"

static const char INDEX_HTML[] =
    "<!doctype html>\n"
    "<html lang=\"en\">\n"
    "<head><meta charset=\"utf-8\"><title>Gazpacho</title></head>\n"
    "<body><h1>Gazpacho</h1>\n"
    "<p>The interface is not built into this program yet. The API answers under /api/v1/.</p>\n"
    "</body>\n"
    "</html>\n";

static const struct {
    const char *path;
    const char *body;
    int is_page;
} FILES[] = {
    {"/", INDEX_HTML, 1},
    {"/index.html", INDEX_HTML, 1},
};

int gz_static_lookup(const char *path, const char **body, size_t *len, int *is_page)
{
    size_t i;
    for (i = 0; i < sizeof FILES / sizeof FILES[0]; i++) {
        if (strcmp(path, FILES[i].path) == 0) {
            *body = FILES[i].body;
            *len = strlen(FILES[i].body);
            *is_page = FILES[i].is_page;
            return 1;
        }
    }
    return 0;
}

/* The interface's pages' headers (5.4), besides the three every answer has. */
const char *gz_page_headers(void)
{
    return "Content-Security-Policy: default-src 'none'; script-src 'self'; style-src 'self'; "
           "img-src 'self'; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; "
           "form-action 'none'; frame-ancestors 'none'; base-uri 'none'; "
           "require-trusted-types-for 'script'; trusted-types 'none'\r\n"
           "Cross-Origin-Opener-Policy: same-origin\r\n"
           "Cross-Origin-Embedder-Policy: require-corp\r\n"
           "X-Frame-Options: DENY\r\n"
           "Permissions-Policy: camera=(), microphone=(), geolocation=(), usb=(), serial=(), "
           "bluetooth=(), payment=(), clipboard-write=()\r\n";
}
