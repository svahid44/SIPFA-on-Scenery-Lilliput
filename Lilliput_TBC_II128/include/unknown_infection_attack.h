#ifndef UNKNOWN_INFECTION_ATTACK_H
#define UNKNOWN_INFECTION_ATTACK_H

#include <stddef.h>
#include <stdint.h>

#include "constants.h"
#include "attack_common.h"

#define LILLIPUT_UNKNOWN_INFECTION_CANDIDATES LILLIPUT_SBOX_DOMAIN

typedef struct lilliput_unknown_infection_result {
    uint64_t final_histogram
        [LILLIPUT_LAST_ROUND_LANES][LILLIPUT_SBOX_DOMAIN];
    uint8_t final_minimum[LILLIPUT_LAST_ROUND_LANES];
    uint64_t final_minimum_count[LILLIPUT_LAST_ROUND_LANES];
    size_t final_minimum_multiplicity[LILLIPUT_LAST_ROUND_LANES];
    double final_lane_sei[LILLIPUT_LAST_ROUND_LANES];
    uint8_t relative_round_tweakey[LILLIPUT_LAST_ROUND_LANES];

    double candidate_lane_sei
        [LILLIPUT_UNKNOWN_INFECTION_CANDIDATES]
        [LILLIPUT_LAST_ROUND_LANES];
    double candidate_sei[LILLIPUT_UNKNOWN_INFECTION_CANDIDATES];
    size_t candidate_rank[LILLIPUT_UNKNOWN_INFECTION_CANDIDATES];

    size_t best_candidate_count;
    uint8_t recovered_delta;
    uint8_t recovered_round_tweakey[ROUND_TWEAKEY_BYTES];
    double best_score;
    double second_best_score;
} lilliput_unknown_infection_result;

/*
 * Algorithm-4-style recovery for an unknown persistent S-box input fault in
 * the presence of an infection-based countermeasure.
 *
 * Attacker inputs:
 *   - every public ciphertext (correct ineffective outputs mixed with random
 *     infected outputs);
 *   - the number of public ciphertexts.
 *
 * The routine does not receive the key, tweak, event labels, injected fault
 * input/output, or the true round tweakey.
 *
 * Lilliput uses one shared 8-bit S-box in all eight nonlinear calls.  The
 * least-frequent final-round value in lane j therefore gives
 *
 *     minimum[j] = delta XOR RTK[31][j],
 *
 * which determines RTK[31] up to the unknown byte delta.  For each of the 256
 * delta candidates, the last round is peeled and the squared Euclidean
 * imbalance (SEI) of the eight penultimate-round byte distributions is
 * accumulated.  The unique maximum identifies delta and RTK[31].
 *
 * Return values:
 *   0  unique final minima and a unique best delta candidate were found
 *  -1  invalid argument
 *  -2  at least one final-round lane has a tied minimum
 *  -3  the largest aggregate SEI is shared by multiple candidates
 */
int lilliput_unknown_infection_recover(
    const uint8_t *ciphertexts,
    size_t sample_count,
    lilliput_unknown_infection_result *result
);

#endif /* UNKNOWN_INFECTION_ATTACK_H */
