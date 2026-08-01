#ifndef KNOWN_INFECTION_ATTACK_H
#define KNOWN_INFECTION_ATTACK_H

#include <stddef.h>
#include <stdint.h>

#include "known_detection_attack.h"
#include "scenery.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct scenery_known_infection_result {
    uint8_t target_sbox;
    uint8_t known_delta;
    uint64_t sample_count;
    uint64_t histogram[SCENERY_ATTACK_DOMAIN];
    uint8_t minimum_value;
    uint64_t minimum_count;
    uint64_t second_minimum_count;
    size_t minimum_multiplicity;
    uint8_t recovered_round_key_word;
    int success;
} scenery_known_infection_result;

typedef struct scenery_known_infection_full_result {
    scenery_known_infection_result per_sbox[SCENERY_ATTACK_SBOXES];
    uint8_t recovered_words[SCENERY_ATTACK_SBOXES];
    uint32_t recovered_round_key;
    size_t successful_sboxes;
    int success;
} scenery_known_infection_full_result;

void scenery_known_infection_result_init(
    scenery_known_infection_result *result,
    uint8_t target_sbox,
    uint8_t known_delta
);

int scenery_known_infection_add_ciphertext(
    scenery_known_infection_result *result,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE]
);

/*
 * Algorithm-3 minimum-frequency recovery for one known faulty logical S-box:
 *
 *     minimum = delta XOR SK_28[j]
 *     SK_28[j] = minimum XOR delta.
 *
 * Unlike detection, the target is generally not absent because random infected
 * outputs fill every bin.  Success therefore requires a unique least-frequent
 * histogram value.
 *
 * Return 0 on a unique minimum, 1 on a tied minimum, and -1 on invalid input.
 */
int scenery_known_infection_recover_word(
    scenery_known_infection_result *result
);


/* Initialize eight independent Algorithm-3 campaigns with one known delta. */
void scenery_known_infection_full_result_init(
    scenery_known_infection_full_result *result,
    uint8_t known_delta
);

/* Add one public infected-or-ineffective ciphertext to its known S-box campaign. */
int scenery_known_infection_full_add_ciphertext(
    scenery_known_infection_full_result *result,
    uint8_t target_sbox,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE]
);

/*
 * Recover all eight 4-bit SK_28 words using the unique minimum-frequency rule
 * and compose the complete external 32-bit SK_28 value.
 * Return 0 only when every campaign has a unique minimum.
 */
int scenery_known_infection_recover_full_round_key(
    scenery_known_infection_full_result *result
);

#ifdef __cplusplus
}
#endif

#endif /* KNOWN_INFECTION_ATTACK_H */
