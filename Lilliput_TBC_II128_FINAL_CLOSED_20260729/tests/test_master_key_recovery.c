#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "cipher.h"
#include "master_key_recovery.h"
#include "reference_validation.h"

#define RANDOM_CASES 256U

static uint64_t next_u64(uint64_t *state)
{
    uint64_t x = *state;

    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static void fill_random(uint64_t *state, uint8_t *output, size_t length)
{
    size_t index = 0U;

    while (index < length) {
        const uint64_t value = next_u64(state);
        for (size_t offset = 0U;
             (offset < 8U) && (index < length);
             ++offset, ++index) {
            output[index] = (uint8_t)(value >> (8U * offset));
        }
    }
}

static int run_case(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    size_t case_index
)
{
    static const uint8_t plaintext[BLOCK_BYTES] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    uint8_t rtk30[ROUND_TWEAKEY_BYTES];
    uint8_t rtk31[ROUND_TWEAKEY_BYTES];
    uint8_t expected_ciphertext[BLOCK_BYTES];
    uint8_t recovered_ciphertext[BLOCK_BYTES];
    lilliput_master_key_recovery_result result;
    int status;

    if ((lilliput_reference_round_tweakey(
             key, tweak, ROUNDS - 2U, rtk30) != 0) ||
        (lilliput_reference_round_tweakey(
             key, tweak, ROUNDS - 1U, rtk31) != 0)) {
        fputs("FAIL: validation RTK derivation failed\n", stderr);
        return 1;
    }

    status = lilliput_recover_master_key_from_rtk30_rtk31(
        tweak,
        rtk30,
        rtk31,
        &result
    );
    if (status != 0) {
        fprintf(stderr,
                "FAIL: case %zu master-key recovery status=%d rank=%zu\n",
                case_index,
                status,
                result.rank);
        return 1;
    }

    if ((result.equation_count != 128U) ||
        (result.rank != 128U) ||
        (result.consistent == 0) ||
        (result.unique == 0) ||
        (result.schedule_verification_passed == 0) ||
        (memcmp(result.recovered_key, key, KEY_BYTES) != 0) ||
        (memcmp(result.recomputed_rtk30,
                rtk30,
                ROUND_TWEAKEY_BYTES) != 0) ||
        (memcmp(result.recomputed_rtk31,
                rtk31,
                ROUND_TWEAKEY_BYTES) != 0)) {
        fprintf(stderr,
                "FAIL: case %zu full-rank key-schedule inversion mismatch\n",
                case_index);
        return 1;
    }

    lilliput_tbc_encrypt(key, tweak, plaintext, expected_ciphertext);
    lilliput_tbc_encrypt(
        result.recovered_key,
        tweak,
        plaintext,
        recovered_ciphertext
    );
    if (memcmp(expected_ciphertext,
               recovered_ciphertext,
               BLOCK_BYTES) != 0) {
        fprintf(stderr,
                "FAIL: case %zu encryption verification mismatch\n",
                case_index);
        return 1;
    }

    return 0;
}

int main(void)
{
    uint64_t state = UINT64_C(0x243F6A8885A308D3);
    uint8_t key[KEY_BYTES];
    uint8_t tweak[TWEAK_BYTES];
    uint8_t rtk[ROUND_TWEAKEY_BYTES] = {0};
    lilliput_master_key_recovery_result result;

    if ((lilliput_recover_master_key_from_rtk30_rtk31(
             NULL, rtk, rtk, &result) != -1) ||
        (lilliput_recover_master_key_from_rtk30_rtk31(
             tweak, NULL, rtk, &result) != -1) ||
        (lilliput_recover_master_key_from_rtk30_rtk31(
             tweak, rtk, NULL, &result) != -1) ||
        (lilliput_recover_master_key_from_rtk30_rtk31(
             tweak, rtk, rtk, NULL) != -1)) {
        fputs("FAIL: master-key recovery argument validation failed\n", stderr);
        return 1;
    }

    for (size_t index = 0U; index < KEY_BYTES; ++index) {
        key[index] = (uint8_t)index;
        tweak[index] = (uint8_t)index;
    }
    if (run_case(key, tweak, 0U) != 0) {
        return 1;
    }

    for (size_t case_index = 1U;
         case_index <= RANDOM_CASES;
         ++case_index) {
        fill_random(&state, key, KEY_BYTES);
        fill_random(&state, tweak, TWEAK_BYTES);
        if (run_case(key, tweak, case_index) != 0) {
            return 1;
        }
    }

    printf("PASS: 128x128 GF(2) schedule inversion recovered the exact "
           "master key for %u random key/tweak cases plus the fixed vector.\n",
           RANDOM_CASES);
    return 0;
}
