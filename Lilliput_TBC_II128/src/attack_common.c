#include <stddef.h>
#include <stdint.h>

#include "attack_common.h"

size_t lilliput_histogram_missing_values(
    const uint64_t histogram[LILLIPUT_SBOX_DOMAIN],
    uint8_t missing_values[LILLIPUT_SBOX_DOMAIN]
)
{
    size_t count = 0U;

    if ((histogram == NULL) || (missing_values == NULL)) {
        return 0U;
    }

    for (size_t value = 0U; value < LILLIPUT_SBOX_DOMAIN; ++value) {
        if (histogram[value] == 0U) {
            missing_values[count] = (uint8_t)value;
            ++count;
        }
    }

    return count;
}
