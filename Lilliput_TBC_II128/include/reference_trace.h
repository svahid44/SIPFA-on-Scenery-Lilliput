#ifndef REFERENCE_TRACE_H
#define REFERENCE_TRACE_H

#include <stdint.h>

#include "constants.h"

/*
 * Validation-only encryption trace.
 *
 * Paper rounds are numbered 1..32, while the implementation indexes them
 * 0..31.  For implementation round q:
 *   paper x_{q+1}[lane]  = state_before_round[q][lane]
 *   paper sk_{q+1}[lane] = round_tweakey[q][lane]
 *   paper y_{q+1}[lane]  = sbox_input[q][lane]
 *
 * Attack code must never depend on this structure or its helpers.
 */
typedef struct lilliput_reference_trace {
    uint8_t state_before_round[ROUNDS][BLOCK_BYTES];
    uint8_t state_after_round[ROUNDS][BLOCK_BYTES];
    uint8_t round_tweakey[ROUNDS][ROUND_TWEAKEY_BYTES];
    uint8_t sbox_input[ROUNDS][ROUND_TWEAKEY_BYTES];
} lilliput_reference_trace;

int lilliput_reference_encrypt_trace(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    const uint8_t plaintext[BLOCK_BYTES],
    uint8_t ciphertext[BLOCK_BYTES],
    lilliput_reference_trace *trace
);

#endif /* REFERENCE_TRACE_H */
