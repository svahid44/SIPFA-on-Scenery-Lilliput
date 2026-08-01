#ifndef UNKNOWN_INFECTION_ATTACK_H
#define UNKNOWN_INFECTION_ATTACK_H

#include <stddef.h>
#include <stdint.h>

#include "scenery.h"
#include "unknown_detection_attack.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCENERY_UNKNOWN_INFECTION_SBOXES 8u
#define SCENERY_UNKNOWN_INFECTION_DOMAIN 16u
#define SCENERY_UNKNOWN_INFECTION_CANDIDATES 16u

typedef struct scenery_unknown_infection_result {
    uint64_t sample_count;
    uint64_t histogram[SCENERY_UNKNOWN_INFECTION_SBOXES]
                      [SCENERY_UNKNOWN_INFECTION_DOMAIN];
    double lane_sei[SCENERY_UNKNOWN_INFECTION_SBOXES];
    size_t lane_rank[SCENERY_UNKNOWN_INFECTION_SBOXES];
    uint8_t minimum_value[SCENERY_UNKNOWN_INFECTION_SBOXES];
    uint64_t minimum_count[SCENERY_UNKNOWN_INFECTION_SBOXES];
    uint64_t second_minimum_count[SCENERY_UNKNOWN_INFECTION_SBOXES];
    size_t minimum_multiplicity[SCENERY_UNKNOWN_INFECTION_SBOXES];

    uint8_t detected_sbox;
    uint8_t detected_public_minimum;
    double best_sei;
    double second_best_sei;
    double sei_gap;
    size_t best_candidate_count;
    int success;
} scenery_unknown_infection_result;

/* Reset all public histograms and metadata. */
void scenery_unknown_infection_result_init(
    scenery_unknown_infection_result *result
);

/*
 * Add one unlabeled public ciphertext from the infection-based oracle.
 * Every logical final-round word is histogrammed simultaneously.  No key,
 * fault location, delta, plaintext, or effective/ineffective label is used.
 */
int scenery_unknown_infection_add_ciphertext(
    scenery_unknown_infection_result *result,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE]
);

/*
 * Algorithm-4 fault-localization stage adapted to SCENERY.
 *
 * For lane j and value x, p_j[x] is the public histogram probability.  The
 * squared Euclidean imbalance is
 *
 *     SEI_j = sum_x (p_j[x] - 1/16)^2.
 *
 * The unique largest SEI identifies the faulty logical S-box.  Its unique
 * minimum-frequency value is
 *
 *     public_minimum = delta XOR SK_28[faulty_sbox].
 *
 * Therefore Step 1 leaves exactly sixteen coupled candidates:
 *
 *     SK_28_word(delta_candidate) = public_minimum XOR delta_candidate.
 *
 * Return values:
 *   0  unique maximum-SEI lane and unique minimum in that lane
 *   1  the largest SEI is tied
 *   2  the detected lane has a tied minimum
 *  -1  invalid input or empty dataset
 */
int scenery_unknown_infection_identify_fault(
    scenery_unknown_infection_result *result
);

/* Convert one delta hypothesis into its coupled last-round key-word guess. */
uint8_t scenery_unknown_infection_key_word_candidate(
    uint8_t public_minimum,
    uint8_t delta_candidate
);


#define SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES \
    SCENERY_UNKNOWN_ACTIVE_CANDIDATES
#define SCENERY_UNKNOWN_INFECTION_MAX_SAMPLES \
    (UINT32_C(1) << 20)

typedef struct scenery_unknown_infection_active_candidate {
    /* Five 4-bit words packed in role order A,B,C,D,E. */
    uint32_t packed_words;
    /* Exact SEI numerator: sum over non-zero 4-bit Walsh masks of T_w^2. */
    uint64_t score_numerator;
    double sei;
    size_t rank;
} scenery_unknown_infection_active_candidate;

typedef struct scenery_unknown_infection_partial_result {
    size_t sample_count;
    uint8_t target_sbox;
    uint8_t public_minimum;
    /* Role order A,B,C,D,E = j-1,j,j+2,j+3,j+4 (mod 8). */
    uint8_t active_sboxes[SCENERY_UNKNOWN_ACTIVE_WORDS];

    uint32_t tested_candidates;
    uint32_t walsh_masks_evaluated;
    uint64_t top_score_numerator;
    uint64_t second_score_numerator;
    double top_sei;
    double second_sei;
    double sei_gap;
    size_t top_candidate_count;
    size_t stored_top_candidate_count;

    /* Bits constant across all maximum-SEI candidates. */
    uint8_t known_bit_masks[SCENERY_UNKNOWN_ACTIVE_WORDS];
    uint8_t known_bit_values[SCENERY_UNKNOWN_ACTIVE_WORDS];
    size_t recovered_active_bits;
    uint8_t recovered_delta;
    int delta_recovered;
    int success;
} scenery_unknown_infection_partial_result;

/*
 * Convert the exact Walsh-domain numerator into the ordinary 16-bin SEI:
 *
 *     SEI = numerator / (16 * sample_count^2).
 */
double scenery_unknown_infection_score_to_sei(
    uint64_t score_numerator,
    size_t sample_count
);

/*
 * Algorithm-4 candidate-key stage adapted to SCENERY without secret-key
 * side information.
 *
 * The routine receives only public infection-based ciphertexts plus the
 * Step-1 outputs (faulty logical S-box and public minimum).  It evaluates all
 * 2^20 active SK_28 candidates.  For every candidate it partially removes
 * round 28 for the target word and computes the exact SEI of the resulting
 * round-27 word distribution.
 *
 * A direct 2^20 x N loop is avoided.  The implementation evaluates all
 * candidates exactly with a 20-dimensional XOR Walsh-Hadamard convolution.
 * score_numerators must provide room for all 2^20 candidates.  top_candidates
 * may be NULL when top_candidate_capacity is zero; the total maximum-score
 * multiplicity is always reported.
 *
 * Candidate packing uses role order A,B,C,D,E from
 * scenery_unknown_active_sboxes().  If role B is constant across every
 * maximum-score candidate, delta is recovered as
 *
 *     delta = public_minimum XOR word_B.
 *
 * Return values:
 *   0  complete exhaustive ranking performed
 *  -1  invalid input/capacity or unsupported sample count
 *  -2  allocation failure
 *  -3  internal exact-transform consistency failure
 */
int scenery_unknown_infection_rank_active_key_candidates(
    const uint8_t *ciphertexts,
    size_t sample_count,
    uint8_t target_sbox,
    uint8_t public_minimum,
    uint64_t *score_numerators,
    size_t score_capacity,
    scenery_unknown_infection_active_candidate *top_candidates,
    size_t top_candidate_capacity,
    scenery_unknown_infection_partial_result *result
);

#define SCENERY_UNKNOWN_INFECTION_EQUIVALENCE_MAX 16u

typedef struct scenery_unknown_infection_equivalence_result {
    size_t sample_count;
    uint8_t target_sbox;
    size_t candidate_count;

    uint64_t score_numerators[SCENERY_UNKNOWN_INFECTION_EQUIVALENCE_MAX];
    uint8_t constant_xor[SCENERY_UNKNOWN_INFECTION_EQUIVALENCE_MAX]
                        [SCENERY_UNKNOWN_INFECTION_EQUIVALENCE_MAX];
    uint8_t constant_xor_valid[SCENERY_UNKNOWN_INFECTION_EQUIVALENCE_MAX]
                              [SCENERY_UNKNOWN_INFECTION_EQUIVALENCE_MAX];
    uint8_t histogram_permutation_equal
        [SCENERY_UNKNOWN_INFECTION_EQUIVALENCE_MAX]
        [SCENERY_UNKNOWN_INFECTION_EQUIVALENCE_MAX];

    size_t unique_exact_sequences;
    size_t xor_equivalence_classes;
    size_t unique_score_count;
    int all_pairs_xor_equivalent;
    int success;
} scenery_unknown_infection_equivalence_result;

/*
 * Audit a rank-1 candidate set for structural indistinguishability under the
 * same one-word partial-decryption observation used by Algorithm 4.
 *
 * For each candidate, the routine computes the complete sequence of recovered
 * previous-round target words and its exact 16-bin SEI numerator.  For every
 * pair (a,b), it then checks whether one constant c exists such that
 *
 *     Y_b[s] = Y_a[s] XOR c
 *
 * for every public sample s.  When this relation holds, the two histograms are
 * permutations for every possible dataset prefix and their SEI scores are
 * necessarily identical.  No secret key, fault delta, plaintext, or event
 * label is accepted by this routine.
 *
 * Return values:
 *   0  audit completed
 *  -1  invalid input or unsupported candidate count
 *  -2  allocation failure
 */
int scenery_unknown_infection_audit_candidate_equivalence(
    const uint8_t *ciphertexts,
    size_t sample_count,
    uint8_t target_sbox,
    const uint32_t *packed_candidates,
    size_t candidate_count,
    scenery_unknown_infection_equivalence_result *result
);

#ifdef __cplusplus
}
#endif

#endif /* UNKNOWN_INFECTION_ATTACK_H */
