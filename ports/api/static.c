/* SPDX-License-Identifier: MIT */
/* Static files, compiled into the program (spec/local-api.md 5.4): no file is
 * read from disk at request time, so there is no path to traverse. The files
 * are the interface's (web/), turned into a table by embed.cmake at build
 * time; only exact paths match, and every other path answers 404. */
#include <string.h>

#include "internal.h"

int gz_static_lookup(const char *path, const char **body, size_t *len, int *is_page, const char **ctype_header)
{
    size_t i;
    for (i = 0; i < gz_static_nfiles; i++) {
        if (strcmp(path, gz_static_files[i].path) == 0) {
            *body = (const char *)gz_static_files[i].body;
            *len = gz_static_files[i].len;
            *is_page = gz_static_files[i].is_page;
            *ctype_header = gz_static_files[i].ctype_header;
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
