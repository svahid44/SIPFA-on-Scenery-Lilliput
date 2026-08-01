#include "scenery.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint64_t splitmix64(uint64_t *state)
{
    uint64_t z;
    *state += UINT64_C(0x9E3779B97F4A7C15);
    z = *state;
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

static void random_bytes(uint64_t *state, uint8_t *data, size_t length)
{
    size_t offset = 0u;
    while (offset < length) {
        uint64_t word = splitmix64(state);
        unsigned int byte;
        for (byte = 0u; byte < 8u && offset < length; ++byte, ++offset) {
            data[offset] = (uint8_t)(word >> (8u * byte));
        }
    }
}

int main(void)
{
    uint64_t state = UINT64_C(0x5343454E45525952);
    size_t test;

    if (scenery_sub_columns(UINT32_C(0)) != UINT32_C(0x00FFFF00)) {
        fputs("FAIL: SubColumns(0) mismatch\n", stderr);
        return 1;
    }

    for (test = 0u; test < 5000u; ++test) {
        uint32_t x = (uint32_t)splitmix64(&state);
        uint32_t y = (uint32_t)splitmix64(&state);
        if (scenery_mix_columns(x ^ y) !=
            (scenery_mix_columns(x) ^ scenery_mix_columns(y))) {
            fprintf(stderr, "FAIL: MixColumns linearity at case %zu\n", test);
            return 1;
        }
    }

    for (test = 0u; test < 10000u; ++test) {
        uint8_t key[SCENERY_KEY_SIZE];
        uint8_t plaintext[SCENERY_BLOCK_SIZE];
        uint8_t ciphertext[SCENERY_BLOCK_SIZE];
        uint8_t recovered[SCENERY_BLOCK_SIZE];
        uint8_t in_place[SCENERY_BLOCK_SIZE];
        scenery_ctx ctx;

        random_bytes(&state, key, sizeof(key));
        random_bytes(&state, plaintext, sizeof(plaintext));

        if (scenery_init(&ctx, key) != 0 ||
            scenery_encrypt_block(&ctx, plaintext, ciphertext) != 0 ||
            scenery_decrypt_block(&ctx, ciphertext, recovered) != 0) {
            fprintf(stderr, "FAIL: API error at random case %zu\n", test);
            return 1;
        }
        if (memcmp(plaintext, recovered, SCENERY_BLOCK_SIZE) != 0) {
            fprintf(stderr, "FAIL: random round trip at case %zu\n", test);
            return 1;
        }

        memcpy(in_place, plaintext, SCENERY_BLOCK_SIZE);
        if (scenery_encrypt_block(&ctx, in_place, in_place) != 0 ||
            scenery_decrypt_block(&ctx, in_place, in_place) != 0 ||
            memcmp(in_place, plaintext, SCENERY_BLOCK_SIZE) != 0) {
            fprintf(stderr, "FAIL: in-place operation at case %zu\n", test);
            return 1;
        }
    }

    puts("PASS: component properties, 10000 round trips, and in-place tests succeeded.");
    return 0;
}
