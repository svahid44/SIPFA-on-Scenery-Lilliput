#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "attack_common.h"
#include "attack_round.h"
#include "constants.h"
#include "unknown_infection_attack.h"

static double squared_euclidean_imbalance(
    const uint64_t histogram[LILLIPUT_SBOX_DOMAIN],
    size_t sample_count
)
{
    const double uniform = 1.0 / (double)LILLIPUT_SBOX_DOMAIN;
    const double denominator = (double)sample_count;
    double sei = 0.0;

    for (size_t value = 0U; value < LILLIPUT_SBOX_DOMAIN; ++value) {
        const double probability = (double)histogram[value] / denominator;
        const double difference = probability - uniform;
        sei += difference * difference;
    }

    return sei;
}

int lilliput_unknown_infection_recover(
    const uint8_t *ciphertexts,
    size_t sample_count,
    lilliput_unknown_infection_result *result
)
{
    if ((ciphertexts == NULL) || (sample_count == 0U) || (result == NULL)) {
        return -1;
    }

    memset(result, 0, sizeof(*result));

    /* Algorithm 4: determine the final-round biased distributions. */
    for (size_t sample = 0U; sample < sample_count; ++sample) {
        const uint8_t *ciphertext = ciphertexts + sample * BLOCK_BYTES;

        for (size_t lane = 0U;
             lane < LILLIPUT_LAST_ROUND_LANES;
             ++lane) {
            ++result->final_histogram[lane][ciphertext[lane]];
        }
    }

    for (size_t lane = 0U;
         lane < LILLIPUT_LAST_ROUND_LANES;
         ++lane) {
        uint64_t minimum = UINT64_MAX;
        size_t multiplicity = 0U;
        uint8_t minimum_value = 0U;

        for (size_t value = 0U; value < LILLIPUT_SBOX_DOMAIN; ++value) {
            const uint64_t count = result->final_histogram[lane][value];

            if (count < minimum) {
                minimum = count;
                minimum_value = (uint8_t)value;
                multiplicity = 1U;
            } else if (count == minimum) {
                ++multiplicity;
            }
        }

        result->final_minimum[lane] = minimum_value;
        result->final_minimum_count[lane] = minimum;
        result->final_minimum_multiplicity[lane] = multiplicity;
        result->final_lane_sei[lane] =
            squared_euclidean_imbalance(
                result->final_histogram[lane],
                sample_count
            );

        if (multiplicity != 1U) {
            return -2;
        }

        result->relative_round_tweakey[lane] =
            (uint8_t)(minimum_value ^ result->final_minimum[0]);
    }

    /*
     * Algorithm 4 candidate-key stage.  Each candidate delta fixes RTK[31].
     * Partial decryption is followed by SEI evaluation of the eight target
     * byte distributions in the penultimate round.
     */
    for (size_t delta = 0U;
         delta < LILLIPUT_UNKNOWN_INFECTION_CANDIDATES;
         ++delta) {
        uint8_t candidate_rtk[ROUND_TWEAKEY_BYTES];
        uint64_t previous_histogram
            [LILLIPUT_LAST_ROUND_LANES][LILLIPUT_SBOX_DOMAIN];

        memset(previous_histogram, 0, sizeof(previous_histogram));

        for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
            candidate_rtk[lane] =
                (uint8_t)(result->final_minimum[lane] ^ (uint8_t)delta);
        }

        for (size_t sample = 0U; sample < sample_count; ++sample) {
            uint8_t state_after_round30[BLOCK_BYTES];
            uint8_t penultimate_inputs[ROUND_TWEAKEY_BYTES];
            const uint8_t *ciphertext = ciphertexts + sample * BLOCK_BYTES;

            lilliput_attack_peel_final_round(
                ciphertext,
                candidate_rtk,
                state_after_round30
            );
            lilliput_attack_extract_penultimate_inputs(
                state_after_round30,
                penultimate_inputs
            );

            for (size_t lane = 0U;
                 lane < LILLIPUT_LAST_ROUND_LANES;
                 ++lane) {
                ++previous_histogram[lane][penultimate_inputs[lane]];
            }
        }

        for (size_t lane = 0U;
             lane < LILLIPUT_LAST_ROUND_LANES;
             ++lane) {
            const double lane_sei =
                squared_euclidean_imbalance(
                    previous_histogram[lane],
                    sample_count
                );

            result->candidate_lane_sei[delta][lane] = lane_sei;
            result->candidate_sei[delta] += lane_sei;
        }
    }

    for (size_t candidate = 0U;
         candidate < LILLIPUT_UNKNOWN_INFECTION_CANDIDATES;
         ++candidate) {
        size_t rank = 1U;

        for (size_t other = 0U;
             other < LILLIPUT_UNKNOWN_INFECTION_CANDIDATES;
             ++other) {
            if (result->candidate_sei[other] >
                result->candidate_sei[candidate]) {
                ++rank;
            }
        }
        result->candidate_rank[candidate] = rank;
    }

    result->best_score = -1.0;
    result->second_best_score = -1.0;
    result->best_candidate_count = 0U;

    for (size_t delta = 0U;
         delta < LILLIPUT_UNKNOWN_INFECTION_CANDIDATES;
         ++delta) {
        const double score = result->candidate_sei[delta];

        if (score > result->best_score) {
            result->second_best_score = result->best_score;
            result->best_score = score;
            result->recovered_delta = (uint8_t)delta;
            result->best_candidate_count = 1U;
        } else if (score == result->best_score) {
            ++result->best_candidate_count;
        } else if (score > result->second_best_score) {
            result->second_best_score = score;
        }
    }

    if (result->best_candidate_count != 1U) {
        return -3;
    }

    for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
        result->recovered_round_tweakey[lane] =
            (uint8_t)(result->final_minimum[lane] ^ result->recovered_delta);
    }

    return 0;
}
