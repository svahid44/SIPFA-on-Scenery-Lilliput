#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "attack_common.h"
#include "attack_round.h"
#include "known_detection_iterative.h"

static int recover_unique_round_tweakey(
    uint64_t histogram
        [LILLIPUT_LAST_ROUND_LANES][LILLIPUT_SBOX_DOMAIN],
    uint8_t delta,
    size_t missing_count[LILLIPUT_LAST_ROUND_LANES],
    uint8_t missing_value[LILLIPUT_LAST_ROUND_LANES],
    uint8_t recovered_rtk[ROUND_TWEAKEY_BYTES]
)
{
    int all_unique = 1;

    for (size_t lane = 0U;
         lane < LILLIPUT_LAST_ROUND_LANES;
         ++lane) {
        uint8_t missing_values[LILLIPUT_SBOX_DOMAIN];
        const size_t count = lilliput_histogram_missing_values(
            histogram[lane], missing_values
        );

        missing_count[lane] = count;
        missing_value[lane] = count > 0U ? missing_values[0] : 0U;

        if (count == 1U) {
            recovered_rtk[lane] = (uint8_t)(missing_values[0] ^ delta);
        } else {
            recovered_rtk[lane] = 0U;
            all_unique = 0;
        }
    }

    return all_unique ? 0 : -1;
}

int lilliput_known_detection_recover_last_two_rtks(
    const uint8_t *accepted_ciphertexts,
    size_t sample_count,
    uint8_t delta,
    lilliput_known_detection_iterative_result *result
)
{
    if ((accepted_ciphertexts == NULL) || (sample_count == 0U) ||
        (result == NULL) || (sample_count > SIZE_MAX / BLOCK_BYTES)) {
        return -1;
    }

    memset(result, 0, sizeof(*result));

    /* Algorithm 1, lines 2--8: recover sk_n = RTK[31]. */
    for (size_t sample = 0U; sample < sample_count; ++sample) {
        const uint8_t *ciphertext =
            accepted_ciphertexts + sample * BLOCK_BYTES;

        for (size_t lane = 0U;
             lane < LILLIPUT_LAST_ROUND_LANES;
             ++lane) {
            ++result->final_histogram[lane][ciphertext[lane]];
        }
    }

    if (recover_unique_round_tweakey(
            result->final_histogram,
            delta,
            result->final_missing_count,
            result->final_missing_value,
            result->recovered_rtk31) != 0) {
        return -2;
    }

    /*
     * Algorithm 1, lines 9--18: remove round n with recovered sk_n and form
     * x_{n-1}.  The same accepted ciphertext dataset is reused.
     */
    for (size_t sample = 0U; sample < sample_count; ++sample) {
        const uint8_t *ciphertext =
            accepted_ciphertexts + sample * BLOCK_BYTES;
        uint8_t state_before_final_round[BLOCK_BYTES];
        uint8_t penultimate_inputs[ROUND_TWEAKEY_BYTES];

        lilliput_attack_peel_final_round(
            ciphertext,
            result->recovered_rtk31,
            state_before_final_round
        );
        lilliput_attack_extract_penultimate_inputs(
            state_before_final_round,
            penultimate_inputs
        );

        for (size_t lane = 0U;
             lane < LILLIPUT_LAST_ROUND_LANES;
             ++lane) {
            ++result->penultimate_histogram[lane][penultimate_inputs[lane]];
        }
    }

    /* Algorithm 1, line 19: recover sk_{n-1} = RTK[30]. */
    if (recover_unique_round_tweakey(
            result->penultimate_histogram,
            delta,
            result->penultimate_missing_count,
            result->penultimate_missing_value,
            result->recovered_rtk30) != 0) {
        return -3;
    }

    return 0;
}
