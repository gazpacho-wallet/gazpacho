/* NOT PART OF GAZPACHO. One forbidden thing per case, each compiled on its
 * own with the core's flags (-DCASE=n) and given to
 * tools/check-core-isolation.sh by tests/isolation/check-sneaky.sh. Cases in
 * the "refused by the check" group must be refused by the object or source
 * check; cases in the "refused by the compiler" group must not compile with
 * the core's flags; cases in the "not caught" group are things the check is
 * known not to catch, kept so the list in the script stays honest. x86-64. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define PASTE(a, b) a##b

/* ---- must be refused by the object check ---- */
#if CASE == 1       /* a system call behind a prefix byte */
long f(void) { long r; __asm__ volatile(".byte 0x66,0x0f,0x05" : "=a"(r) : "a"(39L) : "rcx", "r11", "memory"); return r; }
#elif CASE == 2     /* a system call written as bytes */
long f(void) { long r; __asm__ volatile(".byte 0x0f,0x05" : "=a"(r) : "a"(39L) : "rcx", "r11", "memory"); return r; }
#elif CASE == 3     /* the old system-call interrupt */
long f(void) { long r; __asm__ volatile("int $128" : "=a"(r) : "a"(20L) : "memory"); return r; }
#elif CASE == 4     /* sysenter */
void f(void) { __asm__ volatile("sysenter" ::: "memory"); }
#elif CASE == 5     /* the processor's identity */
uint32_t f(void) { uint32_t a = 1, b, c, d; __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d)); return a ^ b ^ c ^ d; }
#elif CASE == 6     /* a performance counter */
uint64_t f(void) { uint32_t lo, hi; __asm__ volatile("rdpmc" : "=a"(lo), "=d"(hi) : "c"(0)); return ((uint64_t)hi << 32) | lo; }
#elif CASE == 7     /* an extended control register */
uint64_t f(void) { uint32_t lo, hi; __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0)); return ((uint64_t)hi << 32) | lo; }
#elif CASE == 8     /* the processor's random source, written as bytes */
uint64_t f(void) { uint64_t v; __asm__ volatile(".byte 0x48,0x0f,0xc7,0xf0" : "=a"(v)); return v; }
#elif CASE == 9     /* the random source through a builtin, no assembly text */
__attribute__((target("rdrnd"))) int f(unsigned *p) { return __builtin_ia32_rdrand32_step(p); }
#elif CASE == 10    /* the serial number through a builtin */
__attribute__((target("rdpid"))) unsigned f(void) { return __builtin_ia32_rdpid(); }
#elif CASE == 11    /* the thread pointer through a builtin */
__attribute__((target("fsgsbase"))) uint64_t f(void) { return __builtin_ia32_rdfsbase64(); }
#elif CASE == 12    /* the floating-point control word, no floating-point types */
__attribute__((target("sse"))) unsigned f(void) { return __builtin_ia32_stmxcsr(); }
#elif CASE == 13    /* the shadow-stack pointer */
__attribute__((target("shstk"))) uint64_t f(void) { return __builtin_ia32_rdsspq(); }
#elif CASE == 14    /* a hardware transaction */
__attribute__((target("rtm"))) unsigned f(void) { unsigned s = __builtin_ia32_xbegin(); if (s == ~0u) __builtin_ia32_xend(); return s; }
#elif CASE == 15    /* the time-stamp counter through a builtin */
uint64_t f(void) { return __builtin_ia32_rdtsc(); }
#elif CASE == 16    /* a descriptor-table address, assembly spelt by token pasting */
uint64_t f(void) { struct { uint16_t l; uint64_t b; } __attribute__((packed)) d; PASTE(__as, m__) volatile("sgdt %0" : "=m"(d)); return d.b; }
#elif CASE == 17    /* a segment limit, assembly spelt by token pasting */
unsigned f(void) { unsigned v = 0x7b; PASTE(__as, m__) volatile("lsl %0,%0" : "+r"(v)); return v; }
#elif CASE == 18    /* the thread pointer through %gs */
uint64_t f(void) { uint64_t v; __asm__ volatile("movq %%gs:0,%0" : "=r"(v)); return v; }
#elif CASE == 19    /* writable bytes with no symbol */
__asm__(".pushsection .data\n.zero 64\n.popsection");
int f(void) { return 0; }
#elif CASE == 20    /* a variable in a section of its own */
static int n __attribute__((section("mystate")));
int f(void) { return n++; }
#elif CASE == 21    /* a static local */
int f(void) { static int n; return n++; }
#elif CASE == 22    /* thread-local storage */
static _Thread_local int n;
int f(void) { return n++; }
#elif CASE == 23    /* a constructor, which runs before main */
__attribute__((constructor)) static void boot(void) { static volatile int x; x++; }
int f(void) { return 0; }
#elif CASE == 24    /* a checker-exempt name used for ordinary state (caught unless --sanitized) */
static int __asan_sneaky;
int f(void) { return __asan_sneaky++; }
#elif CASE == 25    /* a checker-exempt name used for an outside call */
extern long __sanitizer_now(void);
long f(void) { return __sanitizer_now(); }
#elif CASE == 26    /* a bounds-checked name that is not one of the three allowed */
extern char *__stpcpy_chk(char *, const char *, size_t);
char *f(char *d, const char *s) { return __stpcpy_chk(d, s, 64); }
#elif CASE == 27    /* a mem* name that is not one of the four allowed */
extern void *memfrob(void *, size_t);
void *f(void *p) { return memfrob(p, 8); }
#elif CASE == 28    /* an ifunc resolver: code chosen at load time */
static int impl(void) { return 1; }
static int (*resolve(void))(void) { return impl; }
int f(void) __attribute__((ifunc("resolve")));

/* ---- must be caught by the source scan (inline assembly) ---- */
#elif CASE == 30    /* inline assembly in a header the source includes */
#include "header_asm.h"
unsigned long f(void) { return header_cpu(); }
#elif CASE == 31    /* inline assembly spelt by token pasting (plain, no banned instruction) */
void f(void) { PASTE(__as, m__) volatile("nop"); }

/* ---- must be refused by the compiler ---- */
#elif CASE == 40    /* floating point: refused by -mgeneral-regs-only */
double f(double x) { return x * 1.5 + 0.1; }
/* ---- honest, must pass ---- */
#elif CASE == 50    /* a constant table of pointers */
static const char *const names[] = {"a", "b", "c"};
const char *f(unsigned i) { return names[i % 3]; }
#elif CASE == 51    /* a constant table of functions */
static int one(void) { return 1; }
static int two(void) { return 2; }
static int (*const table[])(void) = {one, two};
int f(unsigned i) { return table[i % 2](); }

/* ---- known not to be caught (listed in the check's own header) ---- */
#elif CASE == 60    /* an address used as data */
uint64_t f(void) { int x; return (uint64_t)(uintptr_t)&x; }
#elif CASE == 61    /* the return address used as data */
uint64_t f(void) { return (uint64_t)(uintptr_t)__builtin_return_address(0); }
#elif CASE == 62    /* the stack-protector value */
uint64_t f(void) { uint64_t v; __asm__ volatile("movq %%fs:0x28,%0" : "=r"(v)); return v; }
#elif CASE == 63    /* the vsyscall page, its address built at run time */
long f(uint64_t k) { volatile uint64_t a = 0x00000000009ffbffull ^ k; return ((long (*)(long *))(uintptr_t)~a)(0); }
#elif CASE == 64    /* a C library function reached by offset from memcpy, an indirect call */
long f(long off) { return ((long (*)(long *))((uintptr_t)memcpy + (uintptr_t)off))(0); }
#endif
