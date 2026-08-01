#ifndef UNKNOWN_DETECTION_ATTACK_H
#define UNKNOWN_DETECTION_ATTACK_H

#include <stddef.h>
#include <stdint.h>

#include "constants.h"
#include "attack_common.h"

#define LILLIPUT_UNKNOWN_DELTA_CANDIDATES LILLIPUT_SBOX_DOMAIN

typedef struct lilliput_unknown_detection_result {
    uint8_t final_missing[LILLIPUT_LAST_ROUND_LANES];
    uint8_t relative_round_tweakey[LILLIPUT_LAST_ROUND_LANES];
    uint16_t previous_round_missing_count
        [LILLIPUT_UNKNOWN_DELTA_CANDIDATES][LILLIPUT_LAST_ROUND_LANES];
    size_t surviving_candidate_count;
    uint8_t surviving_deltas[LILLIPUT_UNKNOWN_DELTA_CANDIDATES];
    uint8_t recovered_delta;
    uint8_t recovered_round_tweakey[ROUND_TWEAKEY_BYTES];
} lilliput_unknown_detection_result;

/*
 * Algorithm-2-style detection-based recovery for an unknown persistent
 * S-box input fault.
 *
 * Attacker inputs:
 *   - ciphertexts accepted by the detection countermeasure (ineffective events)
 *   - number of accepted ciphertexts
 *
 * The routine does not receive the key, tweak, injected fault input/output,
 * or the true round tweakey.
 *
 * Return values:
 *   0  exactly one delta candidate survived and RTK[31] was recovered
 *  -1  invalid argument
 *  -2  final-round histograms do not each have one unique missing value
 *  -3  zero or multiple delta candidates survive the penultimate-round filter
 */
int lilliput_unknown_detection_recover(
    const uint8_t *ciphertexts,
    size_t sample_count,
    lilliput_unknown_detection_result *result
);

#endif /* UNKNOWN_DETECTION_ATTACK_H */
