#include "scenery.h"

#include <stdio.h>
#include <string.h>

typedef struct {
    const char *name;
    uint8_t plaintext[SCENERY_BLOCK_SIZE];
    uint8_t key[SCENERY_KEY_SIZE];
    uint8_t ciphertext[SCENERY_BLOCK_SIZE];
} test_vector;

static const test_vector VECTORS[] = {
    {
        "TV1-zero-plaintext-zero-key",
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x82,0xEF,0xED,0xBA,0x33,0x36,0xCD,0x92}
    },
    {
        "TV2-zero-plaintext-ones-key",
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
        {0xCE,0x6E,0x50,0x05,0xCF,0x04,0xE4,0x26}
    },
    {
        "TV3-ones-plaintext-zero-key",
        {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
        {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
        {0x48,0x0B,0x54,0x21,0xD5,0x61,0x1B,0x60}
    },
    {
        "TV4-ones-plaintext-ones-key",
        {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
        {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF},
        {0xF7,0x52,0xC8,0x4E,0x84,0x12,0x4C,0x59}
    }
};

static void print_hex(const uint8_t *data, size_t length)
{
    size_t i;
    for (i = 0u; i < length; ++i) {
        printf("%02X", data[i]);
    }
}

int main(void)
{
    size_t i;
    size_t passed = 0u;

    for (i = 0u; i < sizeof(VECTORS) / sizeof(VECTORS[0]); ++i) {
        scenery_ctx ctx;
        uint8_t actual[SCENERY_BLOCK_SIZE];
        uint8_t recovered[SCENERY_BLOCK_SIZE];
        int ok;

        if (scenery_init(&ctx, VECTORS[i].key) != 0 ||
            scenery_encrypt_block(&ctx, VECTORS[i].plaintext, actual) != 0 ||
            scenery_decrypt_block(&ctx, VECTORS[i].ciphertext, recovered) != 0) {
            fprintf(stderr, "[FAIL] %s: API error\n", VECTORS[i].name);
            continue;
        }

        ok = memcmp(actual, VECTORS[i].ciphertext, SCENERY_BLOCK_SIZE) == 0 &&
             memcmp(recovered, VECTORS[i].plaintext, SCENERY_BLOCK_SIZE) == 0;

        printf("[%s] %s\n", ok ? "PASS" : "FAIL", VECTORS[i].name);
        printf("  expected C : "); print_hex(VECTORS[i].ciphertext, SCENERY_BLOCK_SIZE); putchar('\n');
        printf("  actual C   : "); print_hex(actual, SCENERY_BLOCK_SIZE); putchar('\n');
        printf("  recovered P: "); print_hex(recovered, SCENERY_BLOCK_SIZE); putchar('\n');

        if (ok) {
            ++passed;
        }
    }

    printf("\nSummary: %zu/%zu official vectors passed\n",
           passed, sizeof(VECTORS) / sizeof(VECTORS[0]));
    return passed == sizeof(VECTORS) / sizeof(VECTORS[0]) ? 0 : 1;
}
