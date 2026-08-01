#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cipher.h"
#include "constants.h"
#include "infection_dataset.h"
#include "persistent_fault.h"
#include "reference_validation.h"
#include "unknown_infection_full_recovery.h"

#define SAMPLE_COUNT ((size_t)100000U)

typedef struct test_case {
    uint8_t delta;
    uint8_t fault_xor;
    uint64_t seed;
} test_case;

typedef struct capture_context {
    uint8_t *ciphertexts;
    size_t capacity;
} capture_context;

static int capture_published(
    uint64_t sample_index,
    const uint8_t ciphertext[BLOCK_BYTES],
    void *user_data
)
{
    capture_context *context = user_data;

    if ((context == NULL) || (sample_index == 0U) ||
        (sample_index > (uint64_t)context->capacity)) {
        return -1;
    }

    memcpy(
        context->ciphertexts + (size_t)(sample_index - 1U) * BLOCK_BYTES,
        ciphertext,
        BLOCK_BYTES
    );
    return 0;
}

static int run_case(const test_case *test)
{
    uint8_t key[KEY_BYTES];
    uint8_t tweak[TWEAK_BYTES];
    uint8_t actual_rtk30[ROUND_TWEAKEY_BYTES];
    uint8_t actual_rtk31[ROUND_TWEAKEY_BYTES];
    uint8_t plaintext[BLOCK_BYTES];
    uint8_t actual_ciphertext[BLOCK_BYTES];
    uint8_t recovered_ciphertext[BLOCK_BYTES];
    uint8_t *published_ciphertexts;
    capture_context capture;
    lilliput_infection_stats stats;
    lilliput_unknown_infection_full_result result;
    int status;

    for (size_t index = 0U; index < KEY_BYTES; ++index) {
        key[index] = (uint8_t)index;
    }
    for (size_t index = 0U; index < TWEAK_BYTES; ++index) {
        tweak[index] = (uint8_t)index;
    }
    for (size_t index = 0U; index < BLOCK_BYTES; ++index) {
        plaintext[index] = (uint8_t)(UINT8_C(0xf0) ^ (uint8_t)index);
    }

    published_ciphertexts = malloc(SAMPLE_COUNT * BLOCK_BYTES);
    if (published_ciphertexts == NULL) {
        fputs("FAIL: could not allocate Scenario-4 dataset\n", stderr);
        return 1;
    }
    capture.ciphertexts = published_ciphertexts;
    capture.capacity = SAMPLE_COUNT;

    lilliput_fault_reset();
    status = lilliput_fault_inject(
        test->delta,
        (uint8_t)(lilliput_sbox_correct(test->delta) ^ test->fault_xor)
    );
    if (status != 0) {
        free(published_ciphertexts);
        fputs("FAIL: persistent fault injection failed\n", stderr);
        return 1;
    }

    status = lilliput_infection_collect(
        key,
        tweak,
        (uint64_t)SAMPLE_COUNT,
        test->seed,
        &stats,
        capture_published,
        &capture
    );
    if (status != 0) {
        lilliput_fault_reset();
        free(published_ciphertexts);
        fputs("FAIL: infection dataset generation failed\n", stderr);
        return 1;
    }

    /*
     * Attack boundary: only unlabeled public ciphertexts, their count, and
     * the public tweak enter the full-recovery routine.
     */
    status = lilliput_unknown_infection_recover_full_key(
        published_ciphertexts,
        SAMPLE_COUNT,
        tweak,
        &result
    );
    if (status != 0) {
        fprintf(stderr,
                "FAIL: full Scenario-4 recovery returned %d for delta=%02x\n",
                status,
                (unsigned)test->delta);
        lilliput_fault_reset();
        free(published_ciphertexts);
        return 1;
    }

    if ((lilliput_reference_round_tweakey(
             key, tweak, ROUNDS - 2U, actual_rtk30) != 0) ||
        (lilliput_reference_round_tweakey(
             key, tweak, ROUNDS - 1U, actual_rtk31) != 0)) {
        lilliput_fault_reset();
        free(published_ciphertexts);
        fputs("FAIL: reference RTK generation failed\n", stderr);
        return 1;
    }

    if ((result.stage1.recovered_delta != test->delta) ||
        (memcmp(result.stage1.recovered_round_tweakey,
                actual_rtk31,
                ROUND_TWEAKEY_BYTES) != 0) ||
        (memcmp(result.recovered_rtk30,
                actual_rtk30,
                ROUND_TWEAKEY_BYTES) != 0) ||
        (memcmp(result.master_key.recovered_key, key, KEY_BYTES) != 0) ||
        (result.master_key.rank != KEY_LENGTH_BITS) ||
        (result.master_key.unique == 0) ||
        (result.master_key.schedule_verification_passed == 0)) {
        lilliput_fault_reset();
        free(published_ciphertexts);
        fputs("FAIL: recovered Scenario-4 secrets do not match ground truth\n",
              stderr);
        return 1;
    }

    for (size_t lane = 0U; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
        if (result.penultimate_minimum_multiplicity[lane] != 1U) {
            lilliput_fault_reset();
            free(published_ciphertexts);
            fputs("FAIL: a penultimate minimum is not unique\n", stderr);
            return 1;
        }
    }

    lilliput_tbc_encrypt(key, tweak, plaintext, actual_ciphertext);
    lilliput_tbc_encrypt(
        result.master_key.recovered_key,
        tweak,
        plaintext,
        recovered_ciphertext
    );
    if (memcmp(actual_ciphertext, recovered_ciphertext, BLOCK_BYTES) != 0) {
        lilliput_fault_reset();
        free(published_ciphertexts);
        fputs("FAIL: recovered master key failed encryption validation\n",
              stderr);
        return 1;
    }

    printf("delta=0x%02x fault_xor=0x%02x samples=%zu rate=%.6f "
           "SEI_gap=%.12e rank=%zu key=PASS\n",
           (unsigned)test->delta,
           (unsigned)test->fault_xor,
           SAMPLE_COUNT,
           (double)stats.internal_ineffective_count /
               (double)stats.published_count,
           result.stage1.best_score - result.stage1.second_best_score,
           result.master_key.rank);

    lilliput_fault_reset();
    free(published_ciphertexts);
    return 0;
}

int main(void)
{
    static const test_case TESTS[] = {
        {UINT8_C(0x00), UINT8_C(0x01),
         UINT64_C(0x510E527FADE682D1)},
        {UINT8_C(0x5a), UINT8_C(0x80),
         UINT64_C(0x9B05688C2B3E6C1F)},
        {UINT8_C(0xff), UINT8_C(0x5a),
         UINT64_C(0x1F83D9ABFB41BD6B)}
    };

    for (size_t index = 0U; index < sizeof(TESTS) / sizeof(TESTS[0]); ++index) {
        if (run_case(&TESTS[index]) != 0) {
            return 1;
        }
    }

    puts("PASS: Scenario 4 recovered unknown delta, RTK[31], RTK[30], and the full 128-bit master key in all test cases.");
    return 0;
}
