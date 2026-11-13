/* The program's hidden KDF mode, on the test library (spec 8.4). With
 * GZ_SC_TEST_FLOOR set it accepts the vectors' test parameters. */
#include "gz_storage_crypto.h"
#include "gz_storage_crypto_test.h"

#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 2 || strcmp(argv[1], "--gz-kdf-helper") != 0)
        return 64;
    if (getenv("GZ_SC_TEST_FLOOR"))
        gz_sc_test_set_floor(1, 8);
    return gz_sc_helper_main(0);
}
