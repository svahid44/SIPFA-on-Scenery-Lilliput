#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "constants.h"
#include "detection_dataset.h"
#include "persistent_fault.h"
#include "reference_validation.h"
#include "unknown_detection_attack.h"

#define TARGET_INEFFECTIVE UINT64_C(4000)
#define MAX_QUERIES        UINT64_C(50000)
#define DATASET_SEED       UINT64_C(0xBB67AE8584CAA73B)
#define SECRET_DELTA       UINT8_C(0x5a)

struct capture_context {
    uint8_t *ciphertexts;
    size_t capacity;
};

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

static int capture_ciphertext(
    uint64_t query_index,
    uint64_t ineffective_index,
    const uint8_t ciphertext[BLOCK_BYTES],
    void *user_data
)
{
    struct capture_context *context = user_data;
    size_t index;

    (void)query_index;

    if ((context == NULL) || (ineffective_index == 0U) ||
        (ineffective_index > context->capacity)) {
        return -1;
    }

    index = (size_t)(ineffective_index - 1U);
    memcpy(context->ciphertexts + index * BLOCK_BYTES, ciphertext, BLOCK_BYTES);
    return 0;
}

int main(void)
{
    uint8_t key[KEY_BYTES];
    uint8_t tweak[TWEAK_BYTES];
    uint8_t actual_rtk[ROUND_TWEAKEY_BYTES];
    uint8_t *ciphertexts;
    lilliput_detection_stats stats;
    lilliput_unknown_detection_result result;
    struct capture_context capture;
    int status;

    for (size_t i = 0; i < KEY_BYTES; ++i) {
        key[i] = (uint8_t)i;
    }
    for (size_t i = 0; i < TWEAK_BYTES; ++i) {
        tweak[i] = (uint8_t)i;
    }

    ciphertexts = malloc((size_t)TARGET_INEFFECTIVE * BLOCK_BYTES);
    if (ciphertexts == NULL) {
        return fail("could not allocate ciphertext dataset");
    }
    capture.ciphertexts = ciphertexts;
    capture.capacity = (size_t)TARGET_INEFFECTIVE;

    lilliput_fault_reset();
    if (lilliput_fault_inject(
            SECRET_DELTA,
            (uint8_t)(lilliput_sbox_correct(SECRET_DELTA) ^ UINT8_C(0x01))) != 0) {
        free(ciphertexts);
        return fail("persistent fault injection failed");
    }

    status = lilliput_detection_collect(key,
                                        tweak,
                                        TARGET_INEFFECTIVE,
                                        MAX_QUERIES,
                                        DATASET_SEED,
                                        &stats,
                                        capture_ciphertext,
                                        &capture);
    if (status != 0) {
        free(ciphertexts);
        return fail("could not collect the requested ineffective dataset");
    }

    /*
     * The attack receives only the accepted ciphertexts.  It is deliberately
     * not passed key, tweak, SECRET_DELTA, or actual_rtk.
     */
    status = lilliput_unknown_detection_recover(
        ciphertexts,
        (size_t)stats.ineffective_count,
        &result
    );
    if (status != 0) {
        fprintf(stderr,
                "FAIL: unknown-detection attack returned %d with %zu survivors\n",
                status,
                result.surviving_candidate_count);
        free(ciphertexts);
        return 1;
    }

    if (lilliput_reference_round_tweakey(
            key, tweak, ROUNDS - 1U, actual_rtk) != 0) {
        free(ciphertexts);
        return fail("could not compute reference final-round tweakey");
    }

    if (result.recovered_delta != SECRET_DELTA) {
        fprintf(stderr,
                "FAIL: recovered delta=%02x actual delta=%02x\n",
                result.recovered_delta,
                SECRET_DELTA);
        free(ciphertexts);
        return 1;
    }
    if (memcmp(result.recovered_round_tweakey,
               actual_rtk,
               ROUND_TWEAKEY_BYTES) != 0) {
        free(ciphertexts);
        return fail("recovered RTK[31] does not match reference schedule");
    }

    for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
        const uint8_t expected_missing =
            (uint8_t)(SECRET_DELTA ^ actual_rtk[lane]);
        if (result.final_missing[lane] != expected_missing) {
            free(ciphertexts);
            return fail("final-round missing value is not theoretical value");
        }
        if (result.previous_round_missing_count[SECRET_DELTA][lane] == 0U) {
            free(ciphertexts);
            return fail("correct delta failed the penultimate-round missing-value filter");
        }
    }

    printf("queries:             %" PRIu64 "\n", stats.total_queries);
    printf("ineffective samples: %" PRIu64 "\n", stats.ineffective_count);
    printf("effective samples:   %" PRIu64 "\n", stats.effective_count);
    printf("ineffective rate:     %.6f\n",
           (double)stats.ineffective_count / (double)stats.total_queries);
    printf("surviving deltas:     %zu\n", result.surviving_candidate_count);
    printf("recovered delta:      0x%02x\n", result.recovered_delta);
    printf("recovered RTK[31]:    ");
    for (size_t lane = 0; lane < ROUND_TWEAKEY_BYTES; ++lane) {
        printf("%02x", result.recovered_round_tweakey[lane]);
    }
    fputc('\n', stdout);

    lilliput_fault_reset();
    free(ciphertexts);
    puts("PASS: Scenario 2 unknown-fault detection recovery verified.");
    return 0;
}
