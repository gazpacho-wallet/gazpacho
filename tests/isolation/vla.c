/* NOT PART OF GAZPACHO. A variable-length array, which the flags the core is
 * compiled with must reject (tests/isolation/check-sneaky.sh). */
#include <stddef.h>

int vla_first(size_t n)
{
    volatile unsigned char buffer[n];
    buffer[0] = 1;
    return buffer[0];
}
