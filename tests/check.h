/* Minimal checking for the plain C test programs. */
#ifndef GAZPACHO_TEST_CHECK_H
#define GAZPACHO_TEST_CHECK_H

#include <stdio.h>

static int check_failures;
static int check_count;

#define CHECK(cond) \
    do { \
        check_count++; \
        if (!(cond)) { \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            check_failures++; \
        } \
    } while (0)

/* Print the result line and return the process exit code. */
static int check_done(void)
{
    if (check_failures) printf("RESULT: FAIL (%d of %d checks)\n", check_failures, check_count);
    else printf("RESULT: PASS (%d checks)\n", check_count);
    return check_failures ? 1 : 0;
}

#endif
