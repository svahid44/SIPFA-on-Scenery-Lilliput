#ifndef KNOWN_INFECTION_ATTACK_H
#define KNOWN_INFECTION_ATTACK_H

#include <stddef.h>
#include <stdint.h>

#include "constants.h"
#include "attack_common.h"

typedef struct lilliput_known_infection_result {
    uint64_t histogram[LILLIPUT_LAST_ROUND_LANES][LILLIPUT_SBOX_DOMAIN];
    uint8_t minimum_value[LILLIPUT_LAST_ROUND_LANES];
    uint64_t minimum_count[LILLIPUT_LAST_ROUND_LANES];
    uint64_t second_minimum_count[LILLIPUT_LAST_ROUND_LANES];
    size_t minimum_multiplicity[LILLIPUT_LAST_ROUND_LANES];
    uint8_t recovered_round_tweakey[ROUND_TWEAKEY_BYTES];
} lilliput_known_infection_result;

/*
 * Algorithm-3-style recovery for a known persistent S-box input fault in the
 * presence of an infection-based countermeasure.
 *
 * Attacker inputs:
 *   - all public ciphertexts (correct ineffective outputs mixed with random
 *     infected outputs);
 *   - the number of public ciphertexts;
 *   - the known faulty S-box input delta.
 *
 * The routine does not receive the key, tweak, internal event labels, faulty
 * S-box output, or the true round tweakey.
 *
 * For each final-round lane, the least frequent public byte is expected to be
 *
 *     delta XOR RTK[31][lane].
 *
 * Return values:
 *   0  every lane has a unique minimum and RTK[31] is recovered
 *  -1  invalid argument
 *  -2  at least one lane has a tied minimum
 */
int lilliput_known_infection_recover(
    const uint8_t *ciphertexts,
    size_t sample_count,
    uint8_t known_delta,
    lilliput_known_infection_result *result
);

#endif /* KNOWN_INFECTION_ATTACK_H */
