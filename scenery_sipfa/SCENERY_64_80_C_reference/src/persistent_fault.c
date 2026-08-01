#include "persistent_fault.h"

#include <stddef.h>
#include <string.h>

static const uint8_t S_CORRECT[SCENERY_SBOX_DOMAIN] = {
    0x6, 0x5, 0xC, 0xA,
    0x1, 0xE, 0x7, 0x9,
    0xB, 0x0, 0x3, 0xD,
    0x8, 0xF, 0x4, 0x2
};

static uint8_t S_FAULTY[SCENERY_LOGICAL_SBOXES][SCENERY_SBOX_DOMAIN];
static int initialized = 0;
static int active = 0;
static uint8_t active_sbox = 0u;
static uint8_t active_input = 0u;
static uint8_t active_output = 0u;

static uint32_t load32_be(const uint8_t input[4])
{
    return ((uint32_t)input[0] << 24) |
           ((uint32_t)input[1] << 16) |
           ((uint32_t)input[2] <<  8) |
           ((uint32_t)input[3]);
}

static void store32_be(uint8_t output[4], uint32_t value)
{
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >>  8);
    output[3] = (uint8_t)value;
}

static void restore_all_tables(void)
{
    size_t sbox;

    for (sbox = 0u; sbox < SCENERY_LOGICAL_SBOXES; ++sbox) {
        memcpy(S_FAULTY[sbox], S_CORRECT, sizeof(S_CORRECT));
    }
}

static void ensure_initialized(void)
{
    if (!initialized) {
        restore_all_tables();
        initialized = 1;
    }
}

void scenery_fault_reset(void)
{
    restore_all_tables();
    initialized = 1;
    active = 0;
    active_sbox = 0u;
    active_input = 0u;
    active_output = 0u;
}

int scenery_fault_inject(
    uint8_t sbox_index,
    uint8_t input,
    uint8_t faulty_output
)
{
    ensure_initialized();

    if (sbox_index >= SCENERY_LOGICAL_SBOXES ||
        input >= SCENERY_SBOX_DOMAIN ||
        faulty_output >= SCENERY_SBOX_DOMAIN ||
        faulty_output == S_CORRECT[input]) {
        return -1;
    }

    /* Exactly one logical S-box entry is faulty at any time. */
    restore_all_tables();
    S_FAULTY[sbox_index][input] = faulty_output;
    active = 1;
    active_sbox = sbox_index;
    active_input = input;
    active_output = faulty_output;
    return 0;
}

int scenery_fault_is_active(void)
{
    return active;
}

uint8_t scenery_fault_sbox_index(void)
{
    return active_sbox;
}

uint8_t scenery_fault_input(void)
{
    return active_input;
}

uint8_t scenery_fault_output(void)
{
    return active_output;
}

uint8_t scenery_fault_correct_output(void)
{
    return S_CORRECT[active_input];
}

uint8_t scenery_sbox_correct(uint8_t input)
{
    return S_CORRECT[input & 0x0Fu];
}

uint8_t scenery_sbox_faulty(uint8_t sbox_index, uint8_t input)
{
    ensure_initialized();

    if (sbox_index >= SCENERY_LOGICAL_SBOXES ||
        input >= SCENERY_SBOX_DOMAIN) {
        return 0u;
    }
    return S_FAULTY[sbox_index][input];
}

static uint32_t scenery_sub_columns_faulty(uint32_t word)
{
    uint8_t rows[4];
    uint8_t output_rows[4] = { 0u, 0u, 0u, 0u };
    unsigned int sbox;

    store32_be(rows, word);

    for (sbox = 0u; sbox < SCENERY_LOGICAL_SBOXES; ++sbox) {
        const uint8_t input =
            (uint8_t)(((rows[0] >> sbox) & 1u) |
                      (((rows[1] >> sbox) & 1u) << 1) |
                      (((rows[2] >> sbox) & 1u) << 2) |
                      (((rows[3] >> sbox) & 1u) << 3));
        const uint8_t substituted = scenery_sbox_faulty(
            (uint8_t)sbox,
            input
        );
        unsigned int row;

        for (row = 0u; row < 4u; ++row) {
            output_rows[row] |=
                (uint8_t)(((substituted >> row) & 1u) << sbox);
        }
    }

    return load32_be(output_rows);
}

static uint32_t scenery_round_function_faulty(
    uint32_t left,
    uint32_t round_key
)
{
    const uint32_t after_add_key = left ^ round_key;
    const uint32_t after_subcolumns =
        scenery_sub_columns_faulty(after_add_key);
    return scenery_mix_columns(after_subcolumns);
}

int scenery_encrypt_block_faulty(
    const scenery_ctx *ctx,
    const uint8_t plaintext[SCENERY_BLOCK_SIZE],
    uint8_t ciphertext[SCENERY_BLOCK_SIZE]
)
{
    uint32_t left;
    uint32_t right;
    size_t round;

    if (ctx == NULL || plaintext == NULL || ciphertext == NULL) {
        return -1;
    }

    left = load32_be(plaintext);
    right = load32_be(plaintext + 4u);

    for (round = 0u; round < SCENERY_ROUNDS; ++round) {
        const uint32_t mixed = scenery_round_function_faulty(
            left,
            ctx->round_keys[round]
        );
        const uint32_t next_left = right ^ mixed;
        const uint32_t next_right = left;

        left = next_left;
        right = next_right;
    }

    /* Same final swap as the validated reference implementation. */
    store32_be(ciphertext, right);
    store32_be(ciphertext + 4u, left);
    return 0;
}
