#include "persistent_fault.h"
#include "scenery.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define SEARCH_LIMIT 4096u

static uint32_t xorshift32(uint32_t *state)
{
    uint32_t value = *state;
    value ^= value << 13;
    value ^= value >> 17;
    value ^= value << 5;
    *state = value;
    return value;
}

static void random_plaintext(
    uint8_t plaintext[SCENERY_BLOCK_SIZE],
    uint32_t *state
)
{
    size_t offset;

    for (offset = 0u; offset < SCENERY_BLOCK_SIZE; offset += 4u) {
        const uint32_t value = xorshift32(state);
        plaintext[offset] = (uint8_t)(value >> 24);
        plaintext[offset + 1u] = (uint8_t)(value >> 16);
        plaintext[offset + 2u] = (uint8_t)(value >> 8);
        plaintext[offset + 3u] = (uint8_t)value;
    }
}

static void print_hex(
    const char *label,
    const uint8_t *data,
    size_t length
)
{
    size_t i;

    printf("%-24s", label);
    for (i = 0u; i < length; ++i) {
        printf("%02" PRIX8, data[i]);
    }
    putchar('\n');
}

int main(void)
{
    const uint8_t key[SCENERY_KEY_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99
    };
    const uint8_t target_sbox = 3u;
    const uint8_t delta = 0x5u;
    scenery_ctx ctx;
    uint8_t plaintext[SCENERY_BLOCK_SIZE];
    uint8_t correct[SCENERY_BLOCK_SIZE];
    uint8_t faulty[SCENERY_BLOCK_SIZE];
    uint8_t repeated_faulty[SCENERY_BLOCK_SIZE];
    uint8_t effective_plaintext[SCENERY_BLOCK_SIZE];
    uint8_t ineffective_plaintext[SCENERY_BLOCK_SIZE];
    uint8_t effective_correct[SCENERY_BLOCK_SIZE];
    uint8_t effective_faulty[SCENERY_BLOCK_SIZE];
    uint8_t correct_output;
    uint8_t faulty_output;
    uint32_t prng_state = UINT32_C(0xC0FFEE01);
    uint32_t trial;
    size_t changed_entries = 0u;
    int found_effective = 0;
    int found_ineffective = 0;

    if (scenery_init(&ctx, key) != 0) {
        fputs("FAIL: scenery_init failed.\n", stderr);
        return 1;
    }

    /* The validated reference path must be unchanged before injection. */
    scenery_fault_reset();
    random_plaintext(plaintext, &prng_state);
    if (scenery_encrypt_block(&ctx, plaintext, correct) != 0 ||
        scenery_encrypt_block_faulty(&ctx, plaintext, faulty) != 0 ||
        memcmp(correct, faulty, SCENERY_BLOCK_SIZE) != 0) {
        fputs("FAIL: correct and faulty paths differ before injection.\n", stderr);
        return 1;
    }

    correct_output = scenery_sbox_correct(delta);

    /*
     * Match the original SIPFA-DES code: replace the selected S-box output
     * by (correct_output + 1) mod 16.
     */
    faulty_output = (uint8_t)((correct_output + 1u) & 0x0Fu);

    if (scenery_fault_inject(
            target_sbox,
            delta,
            faulty_output) != 0) {
        fputs("FAIL: a valid persistent fault was rejected.\n", stderr);
        return 1;
    }

    if (!scenery_fault_is_active() ||
        scenery_fault_sbox_index() != target_sbox ||
        scenery_fault_input() != delta ||
        scenery_fault_correct_output() != correct_output ||
        scenery_fault_output() != faulty_output) {
        fputs("FAIL: persistent-fault metadata is inconsistent.\n", stderr);
        return 1;
    }

    /* Exactly one logical table entry must differ from the reference S-box. */
    for (uint8_t sbox = 0u; sbox < SCENERY_LOGICAL_SBOXES; ++sbox) {
        for (uint8_t input = 0u; input < SCENERY_SBOX_DOMAIN; ++input) {
            if (scenery_sbox_faulty(sbox, input) !=
                scenery_sbox_correct(input)) {
                ++changed_entries;
                if (sbox != target_sbox || input != delta) {
                    fputs("FAIL: an unintended S-box entry changed.\n", stderr);
                    return 1;
                }
            }
        }
    }
    if (changed_entries != 1u) {
        fprintf(stderr,
                "FAIL: expected one changed entry, observed %zu.\n",
                changed_entries);
        return 1;
    }

    for (trial = 0u; trial < SEARCH_LIMIT; ++trial) {
        random_plaintext(plaintext, &prng_state);
        if (scenery_encrypt_block(&ctx, plaintext, correct) != 0 ||
            scenery_encrypt_block_faulty(&ctx, plaintext, faulty) != 0) {
            fputs("FAIL: encryption API error.\n", stderr);
            return 1;
        }

        if (!found_effective &&
            memcmp(correct, faulty, SCENERY_BLOCK_SIZE) != 0) {
            memcpy(effective_plaintext, plaintext, SCENERY_BLOCK_SIZE);
            memcpy(effective_correct, correct, SCENERY_BLOCK_SIZE);
            memcpy(effective_faulty, faulty, SCENERY_BLOCK_SIZE);
            found_effective = 1;
        }

        if (!found_ineffective &&
            memcmp(correct, faulty, SCENERY_BLOCK_SIZE) == 0) {
            memcpy(ineffective_plaintext, plaintext, SCENERY_BLOCK_SIZE);
            found_ineffective = 1;
        }

        if (found_effective && found_ineffective) {
            break;
        }
    }

    if (!found_effective || !found_ineffective) {
        fprintf(stderr,
                "FAIL: both event types were not found in %u trials.\n",
                SEARCH_LIMIT);
        return 1;
    }

    /* The same persistent fault must give the same output on repetition. */
    if (scenery_encrypt_block_faulty(
            &ctx,
            effective_plaintext,
            repeated_faulty) != 0 ||
        memcmp(
            repeated_faulty,
            effective_faulty,
            SCENERY_BLOCK_SIZE) != 0) {
        fputs("FAIL: the fault did not persist deterministically.\n", stderr);
        return 1;
    }

    scenery_fault_reset();
    if (scenery_encrypt_block_faulty(
            &ctx,
            effective_plaintext,
            repeated_faulty) != 0 ||
        memcmp(
            repeated_faulty,
            effective_correct,
            SCENERY_BLOCK_SIZE) != 0) {
        fputs("FAIL: reset did not restore the correct S-box.\n", stderr);
        return 1;
    }

    printf("target logical S-box:   %u\n", target_sbox);
    printf("fault input delta:      0x%X\n", delta);
    printf("correct S-box output:   0x%X\n", correct_output);
    printf("faulty S-box output:    0x%X\n", faulty_output);
    printf("search trials used:     %" PRIu32 "\n", trial + 1u);
    print_hex("effective plaintext:", effective_plaintext, SCENERY_BLOCK_SIZE);
    print_hex("correct ciphertext:", effective_correct, SCENERY_BLOCK_SIZE);
    print_hex("faulty ciphertext:", effective_faulty, SCENERY_BLOCK_SIZE);
    print_hex("ineffective plaintext:", ineffective_plaintext, SCENERY_BLOCK_SIZE);
    puts("PASS: single-entry persistent fault, effective/ineffective events, persistence, and reset verified.");
    return 0;
}
