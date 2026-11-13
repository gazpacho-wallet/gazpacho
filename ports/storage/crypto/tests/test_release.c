/* Test 29 (review F24): the release library has no test entry point, so E2's
 * key file (64 KiB, below the floor) is refused before any derivation. */
#include "gz_storage_crypto.h"

#include <stdio.h>
#include <string.h>

static int hexval(char c)
{
    return c >= '0' && c <= '9' ? c - '0' : c - 'a' + 10;
}

int main(void)
{
    static const char e3[] =
        "475a4b455946494c01f61eee3b63a380a477a063af32b2bbc97c9ff9f01f2c42"
        "25e97398810800000058e8eff8fffdf8d50e058079eb04146501000000030000"
        "004001db6c732c92598e0ec4c658b7addec256f7ead7e5bfcd58d4590055a6d9"
        "f53000fa10f49bb2d3e546b47c43d7411132c46611fcc062b8f817fd206b6b8d"
        "664d14cb326a638d39a55f6d9725781dfe2ebfda6a10e61ac5ad4e5c89249587"
        "f0b22ee319b1d8722d02b00220f5adf8e344355bf93de8004188451e62b38c7a"
        "eeae8735cd00c056759663ca4f9e4b543981498e14e280f9cbdb3f9828e9a894"
        "de90e7439550bb0901ea3010bbac6feb0fc9571de3fa376d99c2457fb1d33c87"
        "2d91bf5fe219ef90549c9741a9c8ff5a3349af6036691511684a86495d4a227e"
        "5aed0e32ecaffb98c1bfb397f294ee51ea6c5fe6b151809e1e6efd403d50c937"
        "772b94294b517d05166c3977dceea32291a7eefc344ef7d1148b8526d67fbfd3"
        "ff6616110f9ee510357504";
    unsigned char kf[GZ_SC_KEYFILE_LEN];
    for (size_t i = 0; i < sizeof kf; i++)
        kf[i] = (unsigned char)(hexval(e3[2 * i]) << 4 | hexval(e3[2 * i + 1]));
    if (gz_sc_init() != GZ_SC_OK) {
        fprintf(stderr, "gz_sc_init failed\n");
        return 1;
    }
    gz_sc_keyfile_info_t info;
    gz_sc_err_t e = gz_sc_keyfile_parse(kf, sizeof kf, kf + 9, &info);
    if (e != GZ_SC_PARAMS_REFUSED) {
        fprintf(stderr, "release build: E2's key file gave %s, expected parameters refused\n", gz_sc_err_text(e));
        return 1;
    }
    /* The helper path refuses the same parameters before starting anything. */
    unsigned char pk[32], salt[16] = {0};
    gz_sc_kdf_params_t p = {1, 3, 64, 1};
    e = gz_sc_kdf_helper("/nonexistent", (const unsigned char *)"x", 1, salt, &p, pk, NULL);
    if (e != GZ_SC_PARAMS_REFUSED) {
        fprintf(stderr, "release helper: %s, expected parameters refused\n", gz_sc_err_text(e));
        return 1;
    }
    printf("release build refuses E2's key file and parameters: passed\n");
    return 0;
}
