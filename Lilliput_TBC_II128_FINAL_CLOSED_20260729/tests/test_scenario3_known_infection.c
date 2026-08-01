#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "constants.h"
#include "detection_dataset.h"
#include "infection_dataset.h"
#include "known_infection_attack.h"
#include "persistent_fault.h"
#include "reference_validation.h"

#define SAMPLE_COUNT ((size_t)100000U)
#define DATASET_SEED UINT64_C(0x3C6EF372FE94F82B)
#define KNOWN_DELTA  UINT8_C(0x5a)

struct capture_context {
    uint8_t *ciphertexts;
    size_t capacity;
};

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

static int capture_published(
    uint64_t sample_index,
    const uint8_t ciphertext[BLOCK_BYTES],
    void *user_data
)
{
    struct capture_context *context = user_data;
    size_t index;

    if ((context == NULL) || (sample_index == 0U) ||
        (sample_index > (uint64_t)context->capacity)) {
        return -1;
    }

    index = (size_t)(sample_index - 1U);
    memcpy(context->ciphertexts + index * BLOCK_BYTES,
           ciphertext,
           BLOCK_BYTES);
    return 0;
}

int main(void)
{
    uint8_t key[KEY_BYTES];
    uint8_t tweak[TWEAK_BYTES];
    uint8_t actual_rtk[ROUND_TWEAKEY_BYTES];
    uint8_t *published_ciphertexts;
    lilliput_infection_stats stats;
    lilliput_known_infection_result result;
    struct capture_context capture;
    int status;

    for (size_t i = 0; i < KEY_BYTES; ++i) {
        key[i] = (uint8_t)i;
    }
    for (size_t i = 0; i < TWEAK_BYTES; ++i) {
        tweak[i] = (uint8_t)i;
    }

    published_ciphertexts = malloc(SAMPLE_COUNT * BLOCK_BYTES);
    if (published_ciphertexts == NULL) {
        return fail("could not allocate public infection dataset");
    }

    capture.ciphertexts = published_ciphertexts;
    capture.capacity = SAMPLE_COUNT;

    lilliput_fault_reset();
    if (lilliput_fault_inject(
            KNOWN_DELTA,
            (uint8_t)(lilliput_sbox_correct(KNOWN_DELTA) ^ UINT8_C(0x01))) != 0) {
        free(published_ciphertexts);
        return fail("persistent fault injection failed");
    }

    status = lilliput_infection_collect(
        key,
        tweak,
        (uint64_t)SAMPLE_COUNT,
        DATASET_SEED,
        &stats,
        capture_published,
        &capture
    );
    if (status != 0) {
        free(published_ciphertexts);
        return fail("could not collect infection-based public outputs");
    }

    if (stats.published_count != (uint64_t)SAMPLE_COUNT) {
        free(published_ciphertexts);
        return fail("published sample counter is inconsistent");
    }
    if (stats.published_count !=
        stats.internal_ineffective_count + stats.internal_effective_count) {
        free(published_ciphertexts);
        return fail("internal event counters are inconsistent");
    }

    /*
     * The attack receives all public outputs, without effective/ineffective
     * labels.  The known fault input is the only fault parameter supplied.
     */
    status = lilliput_known_infection_recover(
        published_ciphertexts,
        SAMPLE_COUNT,
        KNOWN_DELTA,
        &result
    );
    if (status != 0) {
        fprintf(stderr, "FAIL: known-infection attack returned %d\n", status);
        free(published_ciphertexts);
        return 1;
    }

    if (lilliput_reference_round_tweakey(
            key, tweak, ROUNDS - 1U, actual_rtk) != 0) {
        free(published_ciphertexts);
        return fail("could not compute reference final-round tweakey");
    }

    for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
        uint64_t histogram_total = 0U;
        const uint8_t expected_minimum =
            (uint8_t)(KNOWN_DELTA ^ actual_rtk[lane]);

        for (size_t value = 0; value < LILLIPUT_SBOX_DOMAIN; ++value) {
            histogram_total += result.histogram[lane][value];
        }

        if (histogram_total != (uint64_t)SAMPLE_COUNT) {
            free(published_ciphertexts);
            return fail("a lane histogram does not contain every public output");
        }
        if (result.minimum_multiplicity[lane] != 1U) {
            free(published_ciphertexts);
            return fail("a lane does not have a unique least-frequent value");
        }
        if (result.minimum_value[lane] != expected_minimum) {
            fprintf(stderr,
                    "FAIL: lane %zu minimum=%02x expected=%02x\n",
                    lane,
                    result.minimum_value[lane],
                    expected_minimum);
            free(published_ciphertexts);
            return 1;
        }
        if (result.recovered_round_tweakey[lane] != actual_rtk[lane]) {
            free(published_ciphertexts);
            return fail("known-infection recovery did not reproduce RTK[31]");
        }
        if (result.second_minimum_count[lane] <= result.minimum_count[lane]) {
            free(published_ciphertexts);
            return fail("least-frequency separation is not positive");
        }
    }

    {
        const double empirical_rate =
            (double)stats.internal_ineffective_count /
            (double)stats.published_count;

        if ((empirical_rate < 0.25) || (empirical_rate > 0.50)) {
            free(published_ciphertexts);
            return fail("empirical ineffective rate is outside the expected broad interval");
        }

        printf("published samples:    %" PRIu64 "\n", stats.published_count);
        printf("internal ineffective: %" PRIu64 "\n",
               stats.internal_ineffective_count);
        printf("internal effective:   %" PRIu64 "\n",
               stats.internal_effective_count);
        printf("ineffective rate:      %.6f\n", empirical_rate);
    }

    printf("recovered RTK[31]:    ");
    for (size_t lane = 0; lane < ROUND_TWEAKEY_BYTES; ++lane) {
        printf("%02x", result.recovered_round_tweakey[lane]);
    }
    fputc('\n', stdout);

    lilliput_fault_reset();
    free(published_ciphertexts);
    puts("PASS: Scenario 3 known-fault infection-based recovery verified.");
    return 0;
}
