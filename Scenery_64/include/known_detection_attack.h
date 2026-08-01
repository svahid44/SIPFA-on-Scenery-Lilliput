#ifndef KNOWN_DETECTION_ATTACK_H
#define KNOWN_DETECTION_ATTACK_H

#include <stddef.h>
#include <stdint.h>

#include "scenery.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCENERY_ATTACK_SBOXES 8u
#define SCENERY_ATTACK_DOMAIN 16u

typedef struct scenery_known_detection_result {
    uint8_t target_sbox;
    uint8_t known_delta;
    uint64_t sample_count;
    uint64_t histogram[SCENERY_ATTACK_DOMAIN];
    size_t missing_count;
    uint8_t missing_values[SCENERY_ATTACK_DOMAIN];
    uint8_t recovered_round_key_word;
    int success;
} scenery_known_detection_result;

typedef struct scenery_known_detection_full_result {
    scenery_known_detection_result per_sbox[SCENERY_ATTACK_SBOXES];
    uint8_t recovered_words[SCENERY_ATTACK_SBOXES];
    uint32_t recovered_round_key;
    size_t successful_sboxes;
    int success;
} scenery_known_detection_full_result;

/*
 * Extract one logical 4-bit bitslice word from a 32-bit SCENERY state word.
 * Logical S-box index 0 corresponds to bit 0 of each of the four state bytes.
 */
uint8_t scenery_extract_sbox_word(uint32_t bitsliced_word, uint8_t sbox_index);

/*
 * Extract V[j] from a ciphertext, where C = R_29 || L_29 and R_29 = L_28.
 * Therefore the first 32 ciphertext bits expose L_28, immediately before the
 * final-round XOR with SK_28.
 */
uint8_t scenery_last_round_public_word(
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    uint8_t sbox_index
);

void scenery_known_detection_result_init(
    scenery_known_detection_result *result,
    uint8_t target_sbox,
    uint8_t known_delta
);

/* Add one released ineffective ciphertext to the target histogram. */
int scenery_known_detection_add_ciphertext(
    scenery_known_detection_result *result,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE]
);

/* Return all values whose histogram count is zero. */
size_t scenery_histogram_missing_values(
    const uint64_t histogram[SCENERY_ATTACK_DOMAIN],
    uint8_t missing_values[SCENERY_ATTACK_DOMAIN]
);

/*
 * Complete Algorithm-1 word recovery:
 *
 *     missing = delta XOR SK_28[j]
 *     SK_28[j] = missing XOR delta
 *
 * Success requires exactly one missing value.
 * Return 0 on success, 1 when the missing value is not unique, and -1 for an
 * invalid argument.
 */
int scenery_known_detection_recover_word(
    scenery_known_detection_result *result
);

/* Extract the four key bits feeding one logical final-round S-box. */
uint8_t scenery_round_key_sbox_word(
    uint32_t round_key,
    uint8_t sbox_index
);

/* Compose the external 32-bit round key from its eight bitsliced words. */
uint32_t scenery_compose_round_key_sbox_words(
    const uint8_t words[SCENERY_ATTACK_SBOXES]
);

/* Initialize eight independent known-fault campaigns with one known delta. */
void scenery_known_detection_full_result_init(
    scenery_known_detection_full_result *result,
    uint8_t known_delta
);

/* Add a released ineffective ciphertext to its target-S-box campaign. */
int scenery_known_detection_full_add_ciphertext(
    scenery_known_detection_full_result *result,
    uint8_t target_sbox,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE]
);

/*
 * Recover all eight 4-bit SK_28 words and compose the complete 32-bit SK_28.
 * Return 0 only when every campaign contains exactly one missing value.
 */
int scenery_known_detection_recover_full_round_key(
    scenery_known_detection_full_result *result
);

#ifdef __cplusplus
}
#endif

#endif /* KNOWN_DETECTION_ATTACK_H */
