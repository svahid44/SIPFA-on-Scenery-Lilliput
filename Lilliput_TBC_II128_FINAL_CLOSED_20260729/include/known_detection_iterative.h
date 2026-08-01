#ifndef KNOWN_DETECTION_ITERATIVE_H
#define KNOWN_DETECTION_ITERATIVE_H

#include <stddef.h>
#include <stdint.h>

#include "attack_common.h"
#include "constants.h"

/*
 * Result of the known-fault, detection-based iterative SIPFA procedure.
 *
 * Paper notation versus implementation indexing:
 *   sk_n     <-> RTK[31]
 *   sk_{n-1} <-> RTK[30]
 *
 * The two histograms contain only attacker-derived values:
 *   final_histogram       counts x_n from accepted ciphertexts;
 *   penultimate_histogram counts x_{n-1} after one-round partial decryption.
 */
typedef struct lilliput_known_detection_iterative_result {
    uint64_t final_histogram
        [LILLIPUT_LAST_ROUND_LANES][LILLIPUT_SBOX_DOMAIN];
    uint64_t penultimate_histogram
        [LILLIPUT_LAST_ROUND_LANES][LILLIPUT_SBOX_DOMAIN];
    size_t final_missing_count[LILLIPUT_LAST_ROUND_LANES];
    size_t penultimate_missing_count[LILLIPUT_LAST_ROUND_LANES];
    uint8_t final_missing_value[LILLIPUT_LAST_ROUND_LANES];
    uint8_t penultimate_missing_value[LILLIPUT_LAST_ROUND_LANES];
    uint8_t recovered_rtk31[ROUND_TWEAKEY_BYTES];
    uint8_t recovered_rtk30[ROUND_TWEAKEY_BYTES];
} lilliput_known_detection_iterative_result;

/*
 * Apply the known-fault, detection-based procedure of SIPFA Algorithm 1 to
 * Lilliput-TBC-II-128 for the last two rounds.
 *
 * Inputs visible to the attack are exactly:
 *   - accepted/correct ciphertexts returned by the detection countermeasure;
 *   - the known persistent-fault input delta.
 *
 * No plaintext, master key, tweak, event label, actual RTK, or internal trace
 * is accepted by this API.
 *
 * Return values:
 *   0  RTK[31] and RTK[30] each have one missing value per lane;
 *  -1  invalid argument;
 *  -2  RTK[31] is not uniquely recoverable from the supplied dataset;
 *  -3  RTK[30] is not uniquely recoverable after the article's partial
 *      decryption step.
 */
int lilliput_known_detection_recover_last_two_rtks(
    const uint8_t *accepted_ciphertexts,
    size_t sample_count,
    uint8_t delta,
    lilliput_known_detection_iterative_result *result
);

#endif /* KNOWN_DETECTION_ITERATIVE_H */
