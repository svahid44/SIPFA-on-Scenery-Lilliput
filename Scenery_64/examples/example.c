#include "scenery.h"

#include <stdio.h>

static void print_hex(const char *label, const uint8_t *data, size_t length)
{
    size_t i;
    printf("%-12s", label);
    for (i = 0u; i < length; ++i) {
        printf("%02X", data[i]);
    }
    putchar('\n');
}

int main(void)
{
    const uint8_t key[SCENERY_KEY_SIZE] = {0};
    const uint8_t plaintext[SCENERY_BLOCK_SIZE] = {0};
    scenery_ctx ctx;
    uint8_t ciphertext[SCENERY_BLOCK_SIZE];
    uint8_t recovered[SCENERY_BLOCK_SIZE];

    if (scenery_init(&ctx, key) != 0 ||
        scenery_encrypt_block(&ctx, plaintext, ciphertext) != 0 ||
        scenery_decrypt_block(&ctx, ciphertext, recovered) != 0) {
        fputs("SCENERY API error\n", stderr);
        return 1;
    }

    print_hex("Plaintext :", plaintext, sizeof(plaintext));
    print_hex("Key       :", key, sizeof(key));
    print_hex("Ciphertext:", ciphertext, sizeof(ciphertext));
    print_hex("Recovered :", recovered, sizeof(recovered));
    return 0;
}
