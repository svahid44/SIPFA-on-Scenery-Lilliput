#include "scenery.h"

#include <string.h>

static const uint8_t SCENERY_SBOX[16] = {
    0x6, 0x5, 0xC, 0xA,
    0x1, 0xE, 0x7, 0x9,
    0xB, 0x0, 0x3, 0xD,
    0x8, 0xF, 0x4, 0x2
};

static uint8_t rotl8(uint8_t value, unsigned int amount)
{
    amount &= 7u;
    if (amount == 0u) {
        return value;
    }
    return (uint8_t)(((uint8_t)(value << amount)) |
                     ((uint8_t)(value >> (8u - amount))));
}

static uint8_t rotr8(uint8_t value, unsigned int amount)
{
    amount &= 7u;
    if (amount == 0u) {
        return value;
    }
    return (uint8_t)(((uint8_t)(value >> amount)) |
                     ((uint8_t)(value << (8u - amount))));
}

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

/*
 * Rotate the external big-endian 80-bit bit string left by amount bits.
 * Bit index zero is the most-significant bit k0 from the paper.
 */
static void rotl80_bytes(
    const uint8_t input[SCENERY_KEY_SIZE],
    unsigned int amount,
    uint8_t output[SCENERY_KEY_SIZE]
)
{
    unsigned int out_bit;

    amount %= 80u;
    memset(output, 0, SCENERY_KEY_SIZE);

    for (out_bit = 0u; out_bit < 80u; ++out_bit) {
        const unsigned int source_bit = (out_bit + amount) % 80u;
        const unsigned int source_byte = source_bit / 8u;
        const unsigned int source_offset = 7u - (source_bit % 8u);
        const uint8_t bit =
            (uint8_t)((input[source_byte] >> source_offset) & 1u);
        const unsigned int output_byte = out_bit / 8u;
        const unsigned int output_offset = 7u - (out_bit % 8u);

        output[output_byte] |= (uint8_t)(bit << output_offset);
    }
}

uint32_t scenery_sub_columns(uint32_t word)
{
    uint8_t rows[4];
    uint8_t output_rows[4] = { 0u, 0u, 0u, 0u };
    unsigned int bit_index;

    store32_be(rows, word);

    for (bit_index = 0u; bit_index < 8u; ++bit_index) {
        const uint8_t nibble =
            (uint8_t)(((rows[0] >> bit_index) & 1u) |
                      (((rows[1] >> bit_index) & 1u) << 1) |
                      (((rows[2] >> bit_index) & 1u) << 2) |
                      (((rows[3] >> bit_index) & 1u) << 3));
        const uint8_t substituted = SCENERY_SBOX[nibble];
        unsigned int row;

        for (row = 0u; row < 4u; ++row) {
            output_rows[row] |=
                (uint8_t)(((substituted >> row) & 1u) << bit_index);
        }
    }

    return load32_be(output_rows);
}

uint32_t scenery_mix_columns(uint32_t word)
{
    uint8_t input[4];
    uint8_t output[4];
    uint8_t t;
    uint8_t z;

    store32_be(input, word);

    t = (uint8_t)(rotl8(input[1], 1u) ^ rotr8(input[0], 3u));
    output[0] = (uint8_t)(rotr8(input[0], 2u) ^ t);
    output[1] = (uint8_t)(input[1] ^ t);

    z = (uint8_t)(rotl8(input[3], 4u) ^ rotl8(input[2], 1u));
    output[2] = (uint8_t)(input[2] ^ z);
    output[3] = (uint8_t)(rotr8(input[3], 3u) ^ z);

    return load32_be(output);
}

uint32_t scenery_round_function(
    uint32_t left,
    uint32_t round_key,
    uint32_t *after_add_key,
    uint32_t *after_subcolumns
)
{
    const uint32_t added = left ^ round_key;
    const uint32_t substituted = scenery_sub_columns(added);
    const uint32_t mixed = scenery_mix_columns(substituted);

    if (after_add_key != NULL) {
        *after_add_key = added;
    }
    if (after_subcolumns != NULL) {
        *after_subcolumns = substituted;
    }
    return mixed;
}

int scenery_update_key_state(
    uint8_t key_state[SCENERY_KEY_SIZE],
    unsigned int round_number
)
{
    uint8_t input_state[SCENERY_KEY_SIZE];
    uint8_t rotated[SCENERY_KEY_SIZE];
    uint8_t permuted[SCENERY_KEY_SIZE];
    uint8_t v0;
    unsigned int byte_shift;
    unsigned int i;

    if (key_state == NULL || round_number == 0u || round_number > 31u) {
        return -1;
    }

    memcpy(input_state, key_state, SCENERY_KEY_SIZE);

    /* Step 1: S(k12..k15) and S(k28..k31), both low nibbles. */
    key_state[1] = (uint8_t)((key_state[1] & 0xF0u) |
                             SCENERY_SBOX[key_state[1] & 0x0Fu]);
    key_state[3] = (uint8_t)((key_state[3] & 0xF0u) |
                             SCENERY_SBOX[key_state[3] & 0x0Fu]);

    /* Step 2: left cyclic shift of the complete 80-bit state by 11 bits. */
    rotl80_bytes(key_state, 11u, rotated);

    /* Step 3: XOR i4..i0 into post-rotation bits k11..k15. */
    rotated[1] ^= (uint8_t)(round_number & 0x1Fu);

    /* Step 4: DP controlled by input-state bits k14||k15. */
    v0 = (uint8_t)(input_state[1] & 0x03u);
    byte_shift = (unsigned int)((2u * v0) % 10u);
    for (i = 0u; i < SCENERY_KEY_SIZE; ++i) {
        permuted[i] = rotated[(i + byte_shift) % SCENERY_KEY_SIZE];
    }

    memcpy(key_state, permuted, SCENERY_KEY_SIZE);
    return 0;
}

int scenery_generate_round_keys(
    const uint8_t key[SCENERY_KEY_SIZE],
    uint32_t round_keys[SCENERY_ROUNDS]
)
{
    uint8_t key_state[SCENERY_KEY_SIZE];
    size_t round;

    if (key == NULL || round_keys == NULL) {
        return -1;
    }

    memcpy(key_state, key, SCENERY_KEY_SIZE);
    for (round = 0u; round < SCENERY_ROUNDS; ++round) {
        round_keys[round] = load32_be(key_state);
        if (scenery_update_key_state(key_state, (unsigned int)(round + 1u)) != 0) {
            return -2;
        }
    }
    return 0;
}

int scenery_init(
    scenery_ctx *ctx,
    const uint8_t key[SCENERY_KEY_SIZE]
)
{
    if (ctx == NULL || key == NULL) {
        return -1;
    }
    memcpy(ctx->master_key, key, SCENERY_KEY_SIZE);
    return scenery_generate_round_keys(key, ctx->round_keys);
}

static int crypt_block(
    const scenery_ctx *ctx,
    const uint8_t input[SCENERY_BLOCK_SIZE],
    uint8_t output[SCENERY_BLOCK_SIZE],
    int decrypt,
    scenery_round_trace trace[SCENERY_ROUNDS]
)
{
    uint32_t left;
    uint32_t right;
    size_t round;

    if (ctx == NULL || input == NULL || output == NULL) {
        return -1;
    }

    left = load32_be(input);
    right = load32_be(input + 4u);

    for (round = 0u; round < SCENERY_ROUNDS; ++round) {
        const size_t key_index =
            decrypt ? (SCENERY_ROUNDS - 1u - round) : round;
        const uint32_t round_key = ctx->round_keys[key_index];
        uint32_t after_add_key;
        uint32_t after_subcolumns;
        const uint32_t mixed = scenery_round_function(
            left,
            round_key,
            &after_add_key,
            &after_subcolumns
        );
        const uint32_t next_left = right ^ mixed;
        const uint32_t next_right = left;

        if (trace != NULL) {
            trace[round].round_number = round + 1u;
            trace[round].round_key = round_key;
            trace[round].left_in = left;
            trace[round].right_in = right;
            trace[round].after_add_key = after_add_key;
            trace[round].after_subcolumns = after_subcolumns;
            trace[round].after_mixcolumns = mixed;
            trace[round].left_out = next_left;
            trace[round].right_out = next_right;
        }

        left = next_left;
        right = next_right;
    }

    /* Algorithm 1 publishes R_{Nr+1} || L_{Nr+1}. */
    store32_be(output, right);
    store32_be(output + 4u, left);
    return 0;
}

int scenery_encrypt_block_trace(
    const scenery_ctx *ctx,
    const uint8_t plaintext[SCENERY_BLOCK_SIZE],
    uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    scenery_round_trace trace[SCENERY_ROUNDS]
)
{
    return crypt_block(ctx, plaintext, ciphertext, 0, trace);
}

int scenery_decrypt_block_trace(
    const scenery_ctx *ctx,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    uint8_t plaintext[SCENERY_BLOCK_SIZE],
    scenery_round_trace trace[SCENERY_ROUNDS]
)
{
    return crypt_block(ctx, ciphertext, plaintext, 1, trace);
}

int scenery_encrypt_block(
    const scenery_ctx *ctx,
    const uint8_t plaintext[SCENERY_BLOCK_SIZE],
    uint8_t ciphertext[SCENERY_BLOCK_SIZE]
)
{
    return scenery_encrypt_block_trace(ctx, plaintext, ciphertext, NULL);
}

int scenery_decrypt_block(
    const scenery_ctx *ctx,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    uint8_t plaintext[SCENERY_BLOCK_SIZE]
)
{
    return scenery_decrypt_block_trace(ctx, ciphertext, plaintext, NULL);
}
