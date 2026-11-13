/* NOT PART OF GAZPACHO. A header holding inline assembly, included by one case
 * of tests/isolation/cases.c: the source scan must find it after the
 * preprocessor has run, not only in the .c file. */
static inline unsigned long header_cpu(void)
{
    unsigned long v;
    __asm__ volatile("rdpid %0" : "=r"(v));
    return v;
}
