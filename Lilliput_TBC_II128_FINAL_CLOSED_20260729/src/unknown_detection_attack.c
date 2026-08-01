#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "attack_common.h"
#include "attack_round.h"
#include "constants.h"
#include "unknown_detection_attack.h"

int lilliput_unknown_detection_recover(
    const uint8_t *ciphertexts,
    size_t sample_count,
    lilliput_unknown_detection_result *result
)
{
    uint64_t final_histogram
        [LILLIPUT_LAST_ROUND_LANES][LILLIPUT_SBOX_DOMAIN];

    if ((ciphertexts == NULL) || (sample_count == 0U) || (result == NULL)) {
        return -1;
    }

    memset(result, 0, sizeof(*result));
    memset(final_histogram, 0, sizeof(final_histogram));

    for (size_t sample = 0U; sample < sample_count; ++sample) {
        const uint8_t *ciphertext = ciphertexts + sample * BLOCK_BYTES;
        for (size_t lane = 0U;
             lane < LILLIPUT_LAST_ROUND_LANES;
             ++lane) {
            ++final_histogram[lane][ciphertext[lane]];
        }
    }

    /*
     * Algorithm 2, first filter.  Lilliput uses one shared S-box in all eight
     * calls, so every final-round lane exposes one missing value.
     */
    for (size_t lane = 0U;
         lane < LILLIPUT_LAST_ROUND_LANES;
         ++lane) {
        uint8_t missing[LILLIPUT_SBOX_DOMAIN];
        const size_t count =
            lilliput_histogram_missing_values(final_histogram[lane], missing);

        if (count != 1U) {
            return -2;
        }
        result->final_missing[lane] = missing[0];
        result->relative_round_tweakey[lane] =
            (uint8_t)(missing[0] ^ result->final_missing[0]);
    }

    /*
     * Algorithm 2 candidate filter specialized to the shared-S-box design.
     * For each candidate d, RTK31[j] = missing[j] XOR d.  The last round is
     * partially decrypted and the penultimate-round supports are checked.
     */
    for (size_t delta = 0U;
         delta < LILLIPUT_UNKNOWN_DELTA_CANDIDATES;
         ++delta) {
        uint8_t candidate_rtk[ROUND_TWEAKEY_BYTES];
        uint8_t seen
            [LILLIPUT_LAST_ROUND_LANES][LILLIPUT_SBOX_DOMAIN];
        int candidate_survives = 1;

        memset(seen, 0, sizeof(seen));
        for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
            candidate_rtk[lane] =
                (uint8_t)(result->final_missing[lane] ^ (uint8_t)delta);
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
                seen[lane][penultimate_inputs[lane]] = 1U;
            }
        }

        for (size_t lane = 0U;
             lane < LILLIPUT_LAST_ROUND_LANES;
             ++lane) {
            uint16_t missing_count = 0U;

            for (size_t value = 0U;
                 value < LILLIPUT_SBOX_DOMAIN;
                 ++value) {
                if (seen[lane][value] == 0U) {
                    ++missing_count;
                }
            }

            result->previous_round_missing_count[delta][lane] = missing_count;
            if (missing_count == 0U) {
                candidate_survives = 0;
            }
        }

        if (candidate_survives != 0) {
            result->surviving_deltas[result->surviving_candidate_count] =
                (uint8_t)delta;
            ++result->surviving_candidate_count;
        }
    }

    if (result->surviving_candidate_count != 1U) {
        return -3;
    }

    result->recovered_delta = result->surviving_deltas[0];
    for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
        result->recovered_round_tweakey[lane] =
            (uint8_t)(result->final_missing[lane] ^ result->recovered_delta);
    }

    return 0;
}
