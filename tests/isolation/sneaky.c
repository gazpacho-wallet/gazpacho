/* NOT PART OF GAZPACHO. A file that does, on purpose, things the core must
 * never do. It is compiled on its own and given to
 * tools/check-core-isolation.sh, which must refuse it and name each of the
 * problems marked CAUGHT below (tests/isolation/check-sneaky.sh). It is never
 * linked into anything.
 *
 * Two things here are NOT caught by that check, and are kept to say so
 * plainly: using an address as data, and floating point. */
#include <stddef.h>
#include <stdint.h>

static unsigned long sneaky_counter;                    /* CAUGHT: state that survives between calls */
uint8_t sneaky_table[64];                               /* CAUGHT: a writable global */
extern char *getenv(const char *) __attribute__((weak));
extern long time(long *);

unsigned long sneaky_count(void) { return ++sneaky_counter; }

long sneaky_clock(void) { return time(NULL); }          /* CAUGHT: a call outside */

const char *sneaky_environment(void)                    /* CAUGHT: a weak reference */
{
    return getenv ? getenv("HOME") : NULL;
}

#if defined(__x86_64__)
long sneaky_system_call(void)                           /* CAUGHT: getpid by a raw system call */
{
    long result;
    __asm__ volatile("syscall" : "=a"(result) : "a"(39L) : "rcx", "r11", "memory");
    return result;
}

uint64_t sneaky_processor_clock(void)                   /* CAUGHT: the processor's own clock */
{
    return __builtin_ia32_rdtsc();
}
#endif

uint64_t sneaky_address(void)                           /* not caught: an address used as data */
{
    int local;
    return (uint64_t)(uintptr_t)&local;
}

double sneaky_float(double x) { return x * 1.5; }       /* not caught: floating point */
