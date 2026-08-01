#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cipher.h"
#include "persistent_fault.h"

#define SEARCH_LIMIT 4096U

static uint32_t xorshift32(uint32_t *state)
{
    uint32_t x = *state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    *state = x;
    return x;
}

static void set_random_plaintext(uint8_t plaintext[BLOCK_BYTES], uint32_t *state)
{
    for (size_t i = 0; i < BLOCK_BYTES; i += 4) {
        const uint32_t x = xorshift32(state);
        plaintext[i] = (uint8_t)(x >> 24);
        plaintext[i + 1] = (uint8_t)(x >> 16);
        plaintext[i + 2] = (uint8_t)(x >> 8);
        plaintext[i + 3] = (uint8_t)x;
    }
}

static void print_hex(const char *label, const uint8_t *x, size_t n)
{
    printf("%-20s", label);
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
    uint8_t correct[BLOCK_BYTES];
    uint8_t faulty[BLOCK_BYTES];
    uint8_t faulty_repeat[BLOCK_BYTES];
    uint8_t effective_plaintext[BLOCK_BYTES];
    uint8_t ineffective_plaintext[BLOCK_BYTES];
    uint8_t effective_correct[BLOCK_BYTES];
    uint8_t effective_faulty[BLOCK_BYTES];
    int found_effective = 0;
    int found_ineffective = 0;

    for (size_t i = 0; i < KEY_BYTES; ++i) {
        key[i] = (uint8_t)i;
    }
    for (size_t i = 0; i < TWEAK_BYTES; ++i) {
        tweak[i] = (uint8_t)i;
    }

    lilliput_fault_reset();
    uint32_t prng_state = 0xC0FFEE01U;
    set_random_plaintext(plaintext, &prng_state);
    lilliput_tbc_encrypt(key, tweak, plaintext, correct);
    lilliput_tbc_encrypt_faulty(key, tweak, plaintext, faulty);
    if (memcmp(correct, faulty, BLOCK_BYTES) != 0) {
        fprintf(stderr, "FAIL: faulty path differs before fault injection.\n");
        return 1;
    }

    const uint8_t delta = 0x00U;
    const uint8_t correct_output = lilliput_sbox_correct(delta);
    const uint8_t faulty_output = (uint8_t)(correct_output ^ 0x01U);

    if (lilliput_fault_inject(delta, correct_output) != -1) {
        fprintf(stderr, "FAIL: a no-op fault was accepted.\n");
        return 1;
    }
    if (lilliput_fault_is_active()) {
        fprintf(stderr, "FAIL: rejected no-op fault changed the model state.\n");
        return 1;
    }

    /* Verify that injection always models exactly one faulty table entry. */
    {
        const uint8_t second_delta = UINT8_C(0x5a);
        const uint8_t second_correct = lilliput_sbox_correct(second_delta);
        const uint8_t second_faulty = (uint8_t)(second_correct ^ UINT8_C(0x80));

        if (lilliput_fault_inject(delta, faulty_output) != 0 ||
            lilliput_fault_inject(second_delta, second_faulty) != 0) {
            fprintf(stderr, "FAIL: replacing the active single-entry fault failed.\n");
            return 1;
        }
        for (size_t input = 0U; input < 256U; ++input) {
            const uint8_t expected =
                ((uint8_t)input == second_delta)
                    ? second_faulty
                    : lilliput_sbox_correct((uint8_t)input);
            if (lilliput_sbox_faulty((uint8_t)input) != expected) {
                fprintf(stderr,
                        "FAIL: more than one S-box entry is faulty (input=%02zx).\n",
                        input);
                return 1;
            }
        }
        if (lilliput_fault_input() != second_delta) {
            fprintf(stderr, "FAIL: active-fault metadata was not replaced.\n");
            return 1;
        }
        if (lilliput_fault_inject(second_delta, second_correct) != -1) {
            fprintf(stderr, "FAIL: active no-op fault was accepted.\n");
            return 1;
        }
        if ((lilliput_fault_input() != second_delta) ||
            (lilliput_sbox_faulty(second_delta) != second_faulty)) {
            fprintf(stderr, "FAIL: rejected no-op fault changed the active fault.\n");
            return 1;
        }
        lilliput_fault_reset();
    }

    if (lilliput_fault_inject(delta, faulty_output) != 0) {
        fprintf(stderr, "FAIL: valid persistent fault was rejected.\n");
        return 1;
    }

    if (!lilliput_fault_is_active()
        || lilliput_fault_input() != delta
        || lilliput_fault_correct_output() != correct_output
        || lilliput_fault_output() != faulty_output) {
        fprintf(stderr, "FAIL: persistent-fault metadata is inconsistent.\n");
        return 1;
    }

    for (uint32_t counter = 0; counter < SEARCH_LIMIT; ++counter) {
        (void)counter;
        set_random_plaintext(plaintext, &prng_state);
        lilliput_tbc_encrypt(key, tweak, plaintext, correct);
        lilliput_tbc_encrypt_faulty(key, tweak, plaintext, faulty);

        if (!found_effective && memcmp(correct, faulty, BLOCK_BYTES) != 0) {
            memcpy(effective_plaintext, plaintext, BLOCK_BYTES);
            memcpy(effective_correct, correct, BLOCK_BYTES);
            memcpy(effective_faulty, faulty, BLOCK_BYTES);
            found_effective = 1;
        }

        if (!found_ineffective && memcmp(correct, faulty, BLOCK_BYTES) == 0) {
            memcpy(ineffective_plaintext, plaintext, BLOCK_BYTES);
            found_ineffective = 1;
        }

        if (found_effective && found_ineffective) {
            break;
        }
    }

    if (!found_effective || !found_ineffective) {
        fprintf(stderr,
                "FAIL: did not observe both effective and ineffective events in %u trials.\n",
                SEARCH_LIMIT);
        return 1;
    }

    /* The same fault must persist and produce the same result on repetition. */
    lilliput_tbc_encrypt_faulty(
        key, tweak, effective_plaintext, faulty_repeat
    );
    if (memcmp(effective_faulty, faulty_repeat, BLOCK_BYTES) != 0) {
        fprintf(stderr, "FAIL: fault did not persist deterministically.\n");
        return 1;
    }

    lilliput_fault_reset();
    lilliput_tbc_encrypt_faulty(
        key, tweak, effective_plaintext, faulty_repeat
    );
    if (memcmp(effective_correct, faulty_repeat, BLOCK_BYTES) != 0) {
        fprintf(stderr, "FAIL: reset did not restore the correct S-box.\n");
        return 1;
    }

    printf("fault input:         %02" PRIx8 "\n", delta);
    printf("correct S output:    %02" PRIx8 "\n", correct_output);
    printf("faulty S output:     %02" PRIx8 "\n", faulty_output);
    print_hex("effective plaintext:", effective_plaintext, BLOCK_BYTES);
    print_hex("correct ciphertext:", effective_correct, BLOCK_BYTES);
    print_hex("faulty ciphertext:", effective_faulty, BLOCK_BYTES);
    print_hex("ineffective plaintext:", ineffective_plaintext, BLOCK_BYTES);
    puts("PASS: persistent fault, effective event, ineffective event, persistence, and reset verified.");
    return 0;
}
