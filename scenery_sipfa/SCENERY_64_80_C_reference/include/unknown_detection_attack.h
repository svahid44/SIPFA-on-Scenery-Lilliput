#ifndef UNKNOWN_DETECTION_ATTACK_H
#define UNKNOWN_DETECTION_ATTACK_H

#include <stddef.h>
#include <stdint.h>

#include "scenery.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCENERY_UNKNOWN_DETECTION_SBOXES 8u
#define SCENERY_UNKNOWN_DETECTION_DOMAIN 16u
#define SCENERY_UNKNOWN_ACTIVE_WORDS 5u
#define SCENERY_UNKNOWN_ACTIVE_KEY_BITS 20u
#define SCENERY_UNKNOWN_ACTIVE_CANDIDATES (UINT32_C(1) << SCENERY_UNKNOWN_ACTIVE_KEY_BITS)

typedef struct scenery_unknown_detection_result {
    uint64_t sample_count;
    uint64_t histogram[SCENERY_UNKNOWN_DETECTION_SBOXES]
                      [SCENERY_UNKNOWN_DETECTION_DOMAIN];
    size_t missing_count_per_sbox[SCENERY_UNKNOWN_DETECTION_SBOXES];
    uint8_t missing_values[SCENERY_UNKNOWN_DETECTION_SBOXES]
                          [SCENERY_UNKNOWN_DETECTION_DOMAIN];
    size_t total_missing_count;
    uint8_t detected_sbox;
    uint8_t detected_missing_value;
    int success;
} scenery_unknown_detection_result;

typedef struct scenery_unknown_active_candidate {
    /* Five 4-bit words packed in role order A,B,C,D,E (low to high). */
    uint32_t packed_words;
    /* Bit v is one when value v is absent after partial decryption. */
    uint16_t missing_mask;
    uint8_t missing_count;
} scenery_unknown_active_candidate;


typedef struct scenery_unknown_prefix_profile {
    size_t sample_count;
    uint32_t tested_candidates;
    uint64_t candidate_sample_evaluations;
    size_t surviving_candidate_count;
    uint8_t known_bit_masks[SCENERY_UNKNOWN_ACTIVE_WORDS];
    uint8_t known_bit_values[SCENERY_UNKNOWN_ACTIVE_WORDS];
    size_t recovered_active_bits;
    uint8_t recovered_delta;
    int delta_recovered;
} scenery_unknown_prefix_profile;

typedef struct scenery_unknown_partial_result {
    uint64_t sample_count;
    uint8_t target_sbox;
    uint8_t public_missing_value;
    /* Role order A,B,C,D,E = j-1, j, j+2, j+3, j+4 (mod 8). */
    uint8_t active_sboxes[SCENERY_UNKNOWN_ACTIVE_WORDS];
    uint32_t tested_candidates;
    uint64_t candidate_sample_evaluations;
    size_t surviving_candidate_count;
    size_t stored_candidate_count;
    uint64_t candidate_missing_pairs;
    /* Per role: bits constant across every surviving candidate. */
    uint8_t known_bit_masks[SCENERY_UNKNOWN_ACTIVE_WORDS];
    uint8_t known_bit_values[SCENERY_UNKNOWN_ACTIVE_WORDS];
    size_t recovered_active_bits;
    uint8_t recovered_delta;
    int delta_recovered;
    int success;
} scenery_unknown_partial_result;

/* Initialize all histograms and analysis metadata. */
void scenery_unknown_detection_result_init(
    scenery_unknown_detection_result *result
);

/*
 * Add one public ineffective ciphertext. The attack does not receive the
 * faulted S-box index, delta, key, plaintext, or detector-internal labels.
 * It updates the eight final-round public-word histograms simultaneously.
 */
int scenery_unknown_detection_add_ciphertext(
    scenery_unknown_detection_result *result,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE]
);

/*
 * Steps 8--9 of SIPFA Algorithm 2.
 *
 * Search all 8 x 16 histogram cells for zero-frequency values. If exactly one
 * value is missing globally, its row identifies the faulty logical S-box and
 * its column is
 *
 *     missing = delta XOR SK_28[faulty_sbox].
 *
 * Return values:
 *   0  exactly one global missing value was found
 *   1  zero or multiple global missing values remain
 *  -1  invalid argument or empty dataset
 */
int scenery_unknown_detection_identify_fault(
    scenery_unknown_detection_result *result
);

/*
 * Return the five logical SK_28 words that influence output word j of
 * MixColumns(SubColumns(L_28 XOR SK_28)). Role order is:
 *
 *   A = j-1, B = j, C = j+2, D = j+3, E = j+4 (mod 8).
 */
int scenery_unknown_active_sboxes(
    uint8_t target_sbox,
    uint8_t active_sboxes[SCENERY_UNKNOWN_ACTIVE_WORDS]
);

/* Pack/unpack five 4-bit words in role order A,B,C,D,E. */
uint32_t scenery_unknown_pack_active_words(
    const uint8_t words[SCENERY_UNKNOWN_ACTIVE_WORDS]
);

void scenery_unknown_unpack_active_words(
    uint32_t packed_words,
    uint8_t words[SCENERY_UNKNOWN_ACTIVE_WORDS]
);

/* Research-only verification helper: extract the active words from SK_28. */
uint32_t scenery_unknown_pack_round_key_active_words(
    uint32_t round_key,
    uint8_t target_sbox
);

/*
 * Partially invert round 28 for one target logical word. Only the five active
 * SK_28 words are needed. The returned value is the public pre-key word L_27[j]
 * whose histogram must contain a missing value for a valid key candidate.
 */
uint8_t scenery_unknown_partial_decrypt_previous_word(
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    uint8_t target_sbox,
    uint32_t packed_active_words
);

/*
 * Steps 10--16 of SIPFA Algorithm 2 adapted to SCENERY.
 *
 * Exhaustively test all 2^20 active SK_28 candidates, partially decrypt the
 * last round, and keep candidates for which the L_27[target_sbox] histogram
 * has at least one missing value. The attack receives only public ineffective
 * ciphertexts, the detected S-box, and the public missing value from Step 1.
 *
 * candidates may be NULL when candidate_capacity is zero. The total survivor
 * count is always reported; stored_candidate_count is capped by capacity.
 *
 * Return 0 on completion, -1 for invalid input, and -2 on allocation failure.
 */
int scenery_unknown_detection_filter_active_key_candidates(
    const uint8_t *ciphertexts,
    size_t sample_count,
    uint8_t target_sbox,
    uint8_t public_missing_value,
    scenery_unknown_active_candidate *candidates,
    size_t candidate_capacity,
    scenery_unknown_partial_result *result
);

/*
 * Reproducible experiment helper: profile multiple dataset prefixes with one
 * exhaustive 2^20 traversal. Each profile is exactly the result that the
 * Algorithm-2 missing-value filter would obtain for the corresponding prefix,
 * but no candidate list is materialized. sample_points must be strictly
 * increasing and the ciphertext buffer must contain at least the largest
 * requested prefix.
 */
int scenery_unknown_detection_profile_prefixes(
    const uint8_t *ciphertexts,
    const size_t *sample_points,
    size_t point_count,
    uint8_t target_sbox,
    uint8_t public_missing_value,
    scenery_unknown_prefix_profile *profiles
);

#ifdef __cplusplus
}
#endif

#endif /* UNKNOWN_DETECTION_ATTACK_H */
