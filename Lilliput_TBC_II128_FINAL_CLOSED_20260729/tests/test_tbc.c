#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cipher.h"

static void print_hex(const char *label, const uint8_t *x, size_t n)
{
    printf("%-11s", label);
    for (size_t i = 0; i < n; ++i) {
        printf("%02" PRIx8, x[i]);
    }
    putchar('\n');
}

int main(void)
{
    uint8_t key[KEY_BYTES];
    uint8_t tweak[TWEAK_BYTES];
    uint8_t plaintext[BLOCK_BYTES];
    uint8_t ciphertext[BLOCK_BYTES];
    uint8_t recovered[BLOCK_BYTES];
    static const uint8_t expected[BLOCK_BYTES] = {
        0x0e, 0x00, 0xdd, 0x58, 0xba, 0x41, 0x10, 0xfc,
        0xa8, 0x8d, 0xa6, 0xed, 0xca, 0x38, 0xd9, 0x5d
    };

    for (size_t i = 0; i < KEY_BYTES; ++i) key[i] = (uint8_t)i;
    for (size_t i = 0; i < TWEAK_BYTES; ++i) tweak[i] = (uint8_t)i;
    for (size_t i = 0; i < BLOCK_BYTES; ++i) plaintext[i] = (uint8_t)i;

    lilliput_tbc_encrypt(key, tweak, plaintext, ciphertext);
    lilliput_tbc_decrypt(key, tweak, ciphertext, recovered);

    print_hex("key:", key, KEY_BYTES);
    print_hex("tweak:", tweak, TWEAK_BYTES);
    print_hex("plaintext:", plaintext, BLOCK_BYTES);
    print_hex("ciphertext:", ciphertext, BLOCK_BYTES);
    print_hex("expected:", expected, BLOCK_BYTES);
    print_hex("recovered:", recovered, BLOCK_BYTES);

    if (memcmp(ciphertext, expected, BLOCK_BYTES) != 0) {
        fprintf(stderr, "FAIL: ciphertext differs from the official II-128 VHDL test vector.\n");
        return 1;
    }

    if (memcmp(plaintext, recovered, BLOCK_BYTES) != 0) {
        fprintf(stderr, "FAIL: decryption did not recover plaintext.\n");
        return 1;
    }

    puts("PASS: official ciphertext vector and encryption/decryption round-trip succeeded.");
    return 0;
}
