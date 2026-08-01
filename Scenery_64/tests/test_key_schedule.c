#include "scenery.h"

#include <inttypes.h>
#include <stdio.h>

static const uint32_t ZERO_KEY_EXPECTED[SCENERY_ROUNDS] = {
    UINT32_C(0x00000000),
    UINT32_C(0x30013000),
    UINT32_C(0x30000000),
    UINT32_C(0x30033000),
    UINT32_C(0x608C0180),
    UINT32_C(0x4009328C),
    UINT32_C(0x410C0018),
    UINT32_C(0x4007D814),
    UINT32_C(0x64904200),
    UINT32_C(0xB2193276),
    UINT32_C(0xBA238220),
    UINT32_C(0x840CCDD1),
    UINT32_C(0x4662AAA0),
    UINT32_C(0x00324B21),
    UINT32_C(0x9B2AC1B4),
    UINT32_C(0x0F12B940),
    UINT32_C(0xC8F01458),
    UINT32_C(0xB0B3D803),
    UINT32_C(0x19B23D85),
    UINT32_C(0x92B1CBB4),
    UINT32_C(0x8B466F0F),
    UINT32_C(0xADA4AD72),
    UINT32_C(0x0D7DE262),
    UINT32_C(0x668EDB45),
    UINT32_C(0x5B435FF8),
    UINT32_C(0x13BDDADA),
    UINT32_C(0x9A9736C8),
    UINT32_C(0xEFF664D4)
};

int main(void)
{
    const uint8_t key[SCENERY_KEY_SIZE] = {0};
    uint32_t round_keys[SCENERY_ROUNDS];
    size_t i;

    if (scenery_generate_round_keys(key, round_keys) != 0) {
        fputs("FAIL: key expansion API error\n", stderr);
        return 1;
    }
    for (i = 0u; i < SCENERY_ROUNDS; ++i) {
        if (round_keys[i] != ZERO_KEY_EXPECTED[i]) {
            fprintf(stderr,
                    "FAIL: round key %zu expected %08" PRIX32
                    " got %08" PRIX32 "\n",
                    i + 1u, ZERO_KEY_EXPECTED[i], round_keys[i]);
            return 1;
        }
    }
    puts("PASS: all 28 zero-master-key round keys match the reference trace.");
    return 0;
}
