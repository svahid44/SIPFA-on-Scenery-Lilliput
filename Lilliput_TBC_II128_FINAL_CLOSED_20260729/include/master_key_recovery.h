#ifndef MASTER_KEY_RECOVERY_H
#define MASTER_KEY_RECOVERY_H

#include <stddef.h>
#include <stdint.h>

#include "constants.h"

/*
 * Result of the cipher-specific linear inversion of the Lilliput-TBC-II-128
 * tweakey schedule using RTK[30] and RTK[31].
 *
 * This stage follows the final step intended by SIPFA Algorithm 1 after the
 * required round tweakeys have been recovered.  The SIPFA paper does not give
 * Lilliput's key-schedule equations; the mapping below is therefore the exact
 * Lilliput-specific specialization of that final key-recovery step.
 */
typedef struct lilliput_master_key_recovery_result {
    size_t equation_count;
    size_t rank;
    int consistent;
    int unique;
    int schedule_verification_passed;
    uint8_t recovered_key[KEY_BYTES];
    uint8_t recomputed_rtk30[ROUND_TWEAKEY_BYTES];
    uint8_t recomputed_rtk31[ROUND_TWEAKEY_BYTES];
} lilliput_master_key_recovery_result;

/*
 * Recover the 128-bit master key from two recovered 64-bit round tweakeys.
 *
 * Inputs visible to this routine are exactly:
 *   - the public 128-bit tweak;
 *   - attacker-recovered RTK[30];
 *   - attacker-recovered RTK[31].
 *
 * It constructs the affine equations
 *
 *   RTK[r] = A_r K XOR b_r(T),  r in {30,31},
 *
 * stacks them into a 128-by-128 system over GF(2), and solves it using
 * Gaussian elimination.
 *
 * Return values:
 *   0  unique full-rank solution and schedule verification succeeded;
 *  -1  invalid argument;
 *  -2  inconsistent equation system;
 *  -3  rank is below 128, so the key is not unique;
 *  -4  internal schedule recomputation does not match the supplied RTKs.
 */
int lilliput_recover_master_key_from_rtk30_rtk31(
    const uint8_t public_tweak[TWEAK_BYTES],
    const uint8_t recovered_rtk30[ROUND_TWEAKEY_BYTES],
    const uint8_t recovered_rtk31[ROUND_TWEAKEY_BYTES],
    lilliput_master_key_recovery_result *result
);

#endif /* MASTER_KEY_RECOVERY_H */
