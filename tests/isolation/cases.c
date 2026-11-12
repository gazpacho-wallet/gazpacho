/* NOT PART OF GAZPACHO. One forbidden thing per case, each compiled on its
 * own with the core's flags (-DCASE=n) and given to
 * tools/check-core-isolation.sh by tests/isolation/check-sneaky.sh. Cases 1
 * to 14 must be refused by the check, case 15 by the compiler. Cases 20 to 22
 * are things the check is known NOT to catch; they are kept so that the list
 * in the script stays honest. x86-64 only. */
#include <stddef.h>
#include <stdint.h>

#if CASE == 1       /* a system call behind a prefix byte */
long f(void) { long r; __asm__ volatile(".byte 0x66,0x0f,0x05" : "=a"(r) : "a"(39L) : "rcx", "r11", "memory"); return r; }
#elif CASE == 2     /* a system call written as bytes */
long f(void) { long r; __asm__ volatile(".byte 0x0f,0x05" : "=a"(r) : "a"(39L) : "rcx", "r11", "memory"); return r; }
#elif CASE == 3     /* the old system-call interrupt */
long f(void) { long r; __asm__ volatile("int $128" : "=a"(r) : "a"(20L) : "memory"); return r; }
#elif CASE == 4     /* the processor's identity */
uint32_t f(void) { uint32_t a = 1, b, c, d; __asm__ volatile("cpuid" : "+a"(a), "=b"(b), "=c"(c), "=d"(d)); return a ^ b ^ c ^ d; }
#elif CASE == 5     /* a performance counter */
uint64_t f(void) { uint32_t lo, hi; __asm__ volatile("rdpmc" : "=a"(lo), "=d"(hi) : "c"(0)); return ((uint64_t)hi << 32) | lo; }
#elif CASE == 6     /* an extended control register */
uint64_t f(void) { uint32_t lo, hi; __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0)); return ((uint64_t)hi << 32) | lo; }
#elif CASE == 7     /* the processor's random source, written as bytes */
uint64_t f(void) { uint64_t v; __asm__ volatile(".byte 0x48,0x0f,0xc7,0xf0" : "=a"(v)); return v; }
#elif CASE == 8     /* a call to the kernel's fixed entry page */
long f(void) { return ((long (*)(long *))0xffffffffff600400ul)(0); }
#elif CASE == 9     /* the thread pointer */
uint64_t f(void) { uint64_t v; __asm__ volatile("movq %%fs:0,%0" : "=r"(v)); return v; }
#elif CASE == 10    /* writable bytes with no symbol */
__asm__(".pushsection .data\n.zero 64\n.popsection");
int f(void) { return 0; }
#elif CASE == 11    /* writable bytes with no visible symbol, used */
__asm__(".pushsection .data\n.L_hidden: .quad 0\n.popsection");
uint64_t f(void) { uint64_t v; __asm__ volatile("incq .L_hidden(%%rip)\n movq .L_hidden(%%rip),%0" : "=r"(v) : : "memory"); return v; }
#elif CASE == 12    /* a variable in a section of its own */
static int n __attribute__((section("mystate")));
int f(void) { return n++; }
#elif CASE == 13    /* a static local */
int f(void) { static int n; return n++; }
#elif CASE == 14    /* thread-local storage */
static _Thread_local int n;
int f(void) { return n++; }
#elif CASE == 15    /* floating point: refused by -mgeneral-regs-only */
double f(double x) { return x * 1.5 + 0.1; }
#elif CASE == 20    /* NOT CAUGHT: an address used as data */
uint64_t f(void) { int x; return (uint64_t)(uintptr_t)&x; }
#elif CASE == 21    /* NOT CAUGHT: the return address used as data */
uint64_t f(void) { return (uint64_t)(uintptr_t)__builtin_return_address(0); }
#elif CASE == 22    /* NOT CAUGHT: the stack protector's random value */
uint64_t f(void) { uint64_t v; __asm__ volatile("movq %%fs:0x28,%0" : "=r"(v)); return v; }
#endif
