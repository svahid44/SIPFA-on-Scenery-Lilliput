#ifndef SCENERY_H
#define SCENERY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCENERY_BLOCK_SIZE 8u
#define SCENERY_KEY_SIZE   10u
#define SCENERY_ROUNDS     28u

typedef struct {
    uint8_t master_key[SCENERY_KEY_SIZE];
    uint32_t round_keys[SCENERY_ROUNDS];
} scenery_ctx;

typedef struct {
    size_t round_number;
    uint32_t round_key;
    uint32_t left_in;
    uint32_t right_in;
    uint32_t after_add_key;
    uint32_t after_subcolumns;
    uint32_t after_mixcolumns;
    uint32_t left_out;
    uint32_t right_out;
} scenery_round_trace;

/* Initialize a context and generate all 28 round keys. */
int scenery_init(
    scenery_ctx *ctx,
    const uint8_t key[SCENERY_KEY_SIZE]
);

/* Generate round keys from a 10-byte, big-endian master key. */
int scenery_generate_round_keys(
    const uint8_t key[SCENERY_KEY_SIZE],
    uint32_t round_keys[SCENERY_ROUNDS]
);

/* Exposed research helpers matching the paper-compatible Python reference. */
uint32_t scenery_sub_columns(uint32_t word);
uint32_t scenery_mix_columns(uint32_t word);
uint32_t scenery_round_function(
    uint32_t left,
    uint32_t round_key,
    uint32_t *after_add_key,
    uint32_t *after_subcolumns
);

/* Update one 80-bit key state in place for round_number 1..28. */
int scenery_update_key_state(
    uint8_t key_state[SCENERY_KEY_SIZE],
    unsigned int round_number
);

/* Encrypt/decrypt one 64-bit block. Input and output may alias. */
int scenery_encrypt_block(
    const scenery_ctx *ctx,
    const uint8_t plaintext[SCENERY_BLOCK_SIZE],
    uint8_t ciphertext[SCENERY_BLOCK_SIZE]
);

int scenery_decrypt_block(
    const scenery_ctx *ctx,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    uint8_t plaintext[SCENERY_BLOCK_SIZE]
);

/* Trace variants store exactly SCENERY_ROUNDS records when trace != NULL. */
int scenery_encrypt_block_trace(
    const scenery_ctx *ctx,
    const uint8_t plaintext[SCENERY_BLOCK_SIZE],
    uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    scenery_round_trace trace[SCENERY_ROUNDS]
);

int scenery_decrypt_block_trace(
    const scenery_ctx *ctx,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    uint8_t plaintext[SCENERY_BLOCK_SIZE],
    scenery_round_trace trace[SCENERY_ROUNDS]
);

#ifdef __cplusplus
}
#endif

#endif /* SCENERY_H */
