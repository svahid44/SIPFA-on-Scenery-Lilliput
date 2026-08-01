#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "attack_round.h"
#include "constants.h"
#include "master_key_recovery.h"
#include "unknown_infection_attack.h"
#include "unknown_infection_full_recovery.h"

static int recover_penultimate_rtk(
    const uint8_t *published_ciphertexts,
    size_t sample_count,
    lilliput_unknown_infection_full_result *result
)
{
    for (size_t sample = 0U; sample < sample_count; ++sample) {
        const uint8_t *ciphertext =
            published_ciphertexts + sample * BLOCK_BYTES;
        uint8_t state_before_final_round[BLOCK_BYTES];
        uint8_t penultimate_inputs[ROUND_TWEAKEY_BYTES];

        lilliput_attack_peel_final_round(
            ciphertext,
            result->stage1.recovered_round_tweakey,
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

    for (size_t lane = 0U;
         lane < LILLIPUT_LAST_ROUND_LANES;
         ++lane) {
        uint64_t minimum = UINT64_MAX;
        uint64_t second_minimum = UINT64_MAX;
        size_t multiplicity = 0U;
        uint8_t minimum_value = 0U;

        for (size_t value = 0U; value < LILLIPUT_SBOX_DOMAIN; ++value) {
            const uint64_t count =
                result->penultimate_histogram[lane][value];

            if (count < minimum) {
                second_minimum = minimum;
                minimum = count;
                minimum_value = (uint8_t)value;
                multiplicity = 1U;
            } else if (count == minimum) {
                ++multiplicity;
            } else if (count < second_minimum) {
                second_minimum = count;
            }
        }

        result->penultimate_minimum[lane] = minimum_value;
        result->penultimate_minimum_count[lane] = minimum;
        result->penultimate_second_minimum_count[lane] = second_minimum;
        result->penultimate_minimum_multiplicity[lane] = multiplicity;

        if (multiplicity != 1U) {
            return -3;
        }

        result->recovered_rtk30[lane] =
            (uint8_t)(minimum_value ^ result->stage1.recovered_delta);
    }

    return 0;
}

int lilliput_unknown_infection_recover_full_key(
    const uint8_t *published_ciphertexts,
    size_t sample_count,
    const uint8_t public_tweak[TWEAK_BYTES],
    lilliput_unknown_infection_full_result *result
)
{
    int status;

    if ((published_ciphertexts == NULL) || (sample_count == 0U) ||
        (public_tweak == NULL) || (result == NULL) ||
        (sample_count > SIZE_MAX / BLOCK_BYTES)) {
        return -1;
    }

    memset(result, 0, sizeof(*result));

    result->stage1_status = lilliput_unknown_infection_recover(
        published_ciphertexts,
        sample_count,
        &result->stage1
    );
    if (result->stage1_status != 0) {
        return -2;
    }

    status = recover_penultimate_rtk(
        published_ciphertexts,
        sample_count,
        result
    );
    if (status != 0) {
        return status;
    }

    result->master_key_status =
        lilliput_recover_master_key_from_rtk30_rtk31(
            public_tweak,
            result->recovered_rtk30,
            result->stage1.recovered_round_tweakey,
            &result->master_key
        );
    if (result->master_key_status != 0) {
        return -4;
    }

    return 0;
}
