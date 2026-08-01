#ifndef REFERENCE_VALIDATION_H
#define REFERENCE_VALIDATION_H

#include <stddef.h>
#include <stdint.h>

#include "constants.h"

/*
 * Validation-only helper.  Attack routines must not call this function.
 * It derives the ground-truth round tweakey from the reference key schedule.
 */
int lilliput_reference_round_tweakey(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    size_t round_index,
    uint8_t round_tweakey[ROUND_TWEAKEY_BYTES]
);

#endif /* REFERENCE_VALIDATION_H */
