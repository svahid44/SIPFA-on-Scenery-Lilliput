#ifndef ATTACK_COMMON_H
#define ATTACK_COMMON_H

#include <stddef.h>
#include <stdint.h>

#include "constants.h"

#define LILLIPUT_SBOX_DOMAIN 256U
#define LILLIPUT_LAST_ROUND_LANES ROUND_TWEAKEY_BYTES

/* Return all byte values whose histogram count is zero. */
size_t lilliput_histogram_missing_values(
    const uint64_t histogram[LILLIPUT_SBOX_DOMAIN],
    uint8_t missing_values[LILLIPUT_SBOX_DOMAIN]
);

#endif /* ATTACK_COMMON_H */
