#ifndef UNKNOWN_INFECTION_FULL_RECOVERY_H
#define UNKNOWN_INFECTION_FULL_RECOVERY_H

#include <stddef.h>
#include <stdint.h>

#include "constants.h"
#include "master_key_recovery.h"
#include "unknown_infection_attack.h"

/*
 * Complete Scenario-4 result for Lilliput-TBC-II-128.
 *
 * Stage 1 applies the existing Algorithm-4-style SEI procedure to recover the
 * unknown persistent-fault input and RTK[31].  The same unlabeled public
 * ciphertext dataset is then peeled by one round.  The least-frequent value
 * in each penultimate-round lane yields RTK[30], after which the public tweak
 * and the two recovered RTKs determine the 128-bit master key over GF(2).
 */
typedef struct lilliput_unknown_infection_full_result {
    lilliput_unknown_infection_result stage1;
    int stage1_status;

    uint64_t penultimate_histogram
        [LILLIPUT_LAST_ROUND_LANES][LILLIPUT_SBOX_DOMAIN];
    uint8_t penultimate_minimum[LILLIPUT_LAST_ROUND_LANES];
    uint64_t penultimate_minimum_count[LILLIPUT_LAST_ROUND_LANES];
    uint64_t penultimate_second_minimum_count[LILLIPUT_LAST_ROUND_LANES];
    size_t penultimate_minimum_multiplicity[LILLIPUT_LAST_ROUND_LANES];
    uint8_t recovered_rtk30[ROUND_TWEAKEY_BYTES];

    lilliput_master_key_recovery_result master_key;
    int master_key_status;
} lilliput_unknown_infection_full_result;

/*
 * Attacker-visible inputs:
 *   - unlabeled public ciphertexts emitted by the infection countermeasure;
 *   - the public sample count;
 *   - the public tweak.
 *
 * The function does not receive the master key, plaintexts, event labels,
 * injected fault input/output, actual RTKs, or validation traces.
 *
 * Return values:
 *   0  delta, RTK[31], RTK[30], and the unique 128-bit master key recovered;
 *  -1  invalid argument;
 *  -2  the Algorithm-4-style delta/RTK[31] stage failed;
 *  -3  at least one penultimate lane has a tied minimum;
 *  -4  the GF(2) master-key recovery stage failed.
 */
int lilliput_unknown_infection_recover_full_key(
    const uint8_t *published_ciphertexts,
    size_t sample_count,
    const uint8_t public_tweak[TWEAK_BYTES],
    lilliput_unknown_infection_full_result *result
);

#endif /* UNKNOWN_INFECTION_FULL_RECOVERY_H */
