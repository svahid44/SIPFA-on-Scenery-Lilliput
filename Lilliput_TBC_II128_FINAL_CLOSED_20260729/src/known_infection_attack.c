#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "known_infection_attack.h"

int lilliput_known_infection_recover(
    const uint8_t *ciphertexts,
    size_t sample_count,
    uint8_t known_delta,
    lilliput_known_infection_result *result
)
{
    if ((ciphertexts == NULL) || (sample_count == 0U) || (result == NULL)) {
        return -1;
    }

    memset(result, 0, sizeof(*result));

    for (size_t sample = 0; sample < sample_count; ++sample) {
        const uint8_t *ciphertext = ciphertexts + sample * BLOCK_BYTES;
        for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
            ++result->histogram[lane][ciphertext[lane]];
        }
    }

    for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
        uint64_t minimum = UINT64_MAX;
        uint64_t second_minimum = UINT64_MAX;
        size_t minimum_multiplicity = 0U;
        uint8_t minimum_value = 0U;

        for (size_t value = 0; value < LILLIPUT_SBOX_DOMAIN; ++value) {
            const uint64_t count = result->histogram[lane][value];

            if (count < minimum) {
                second_minimum = minimum;
                minimum = count;
                minimum_value = (uint8_t)value;
                minimum_multiplicity = 1U;
            } else if (count == minimum) {
                ++minimum_multiplicity;
            } else if (count < second_minimum) {
                second_minimum = count;
            }
        }

        result->minimum_value[lane] = minimum_value;
        result->minimum_count[lane] = minimum;
        result->second_minimum_count[lane] = second_minimum;
        result->minimum_multiplicity[lane] = minimum_multiplicity;

        if (minimum_multiplicity != 1U) {
            return -2;
        }

        result->recovered_round_tweakey[lane] =
            (uint8_t)(minimum_value ^ known_delta);
    }

    return 0;
}
