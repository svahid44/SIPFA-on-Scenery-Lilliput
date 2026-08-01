#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "attack_common.h"
#include "constants.h"
#include "detection_dataset.h"
#include "persistent_fault.h"
#include "reference_validation.h"

#define TARGET_INEFFECTIVE UINT64_C(4000)
#define MAX_QUERIES        UINT64_C(50000)

typedef struct scenario1_case {
    uint8_t delta;
    uint8_t fault_xor;
    uint64_t seed;
} scenario1_case;

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

static int run_case(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    const scenario1_case *test_case
)
{
    uint8_t actual_rtk[ROUND_TWEAKEY_BYTES];
    uint8_t recovered_rtk[ROUND_TWEAKEY_BYTES];
    lilliput_detection_stats stats;
    const uint8_t faulty_output =
        (uint8_t)(lilliput_sbox_correct(test_case->delta) ^
                  test_case->fault_xor);

    lilliput_fault_reset();
    if (lilliput_fault_inject(test_case->delta, faulty_output) != 0) {
        return fail("persistent fault injection failed");
    }

    if (lilliput_detection_collect(
            key,
            tweak,
            TARGET_INEFFECTIVE,
            MAX_QUERIES,
            test_case->seed,
            &stats,
            NULL,
            NULL) != 0) {
        return fail("could not collect the requested ineffective dataset");
    }

    if (stats.total_queries !=
        stats.ineffective_count + stats.effective_count) {
        return fail("dataset counters are inconsistent");
    }

    if (lilliput_reference_round_tweakey(
            key,
            tweak,
            ROUNDS - 1U,
            actual_rtk) != 0) {
        return fail("could not compute validation RTK[31]");
    }

    for (size_t lane = 0U;
         lane < LILLIPUT_LAST_ROUND_LANES;
         ++lane) {
        uint8_t missing[LILLIPUT_SBOX_DOMAIN];
        const size_t missing_count =
            lilliput_histogram_missing_values(
                stats.histogram[lane],
                missing
            );
        const uint8_t expected_missing =
            (uint8_t)(test_case->delta ^ actual_rtk[lane]);
        uint64_t histogram_total = 0U;

        for (size_t value = 0U;
             value < LILLIPUT_SBOX_DOMAIN;
             ++value) {
            histogram_total += stats.histogram[lane][value];
        }

        if (histogram_total != TARGET_INEFFECTIVE) {
            return fail("a lane histogram omits accepted ciphertexts");
        }
        if (missing_count != 1U) {
            fprintf(stderr,
                    "FAIL: delta=%02x lane=%zu has %zu missing values\n",
                    test_case->delta,
                    lane,
                    missing_count);
            return 1;
        }
        if (missing[0] != expected_missing) {
            fprintf(stderr,
                    "FAIL: delta=%02x lane=%zu missing=%02x expected=%02x\n",
                    test_case->delta,
                    lane,
                    missing[0],
                    expected_missing);
            return 1;
        }

        recovered_rtk[lane] =
            (uint8_t)(missing[0] ^ test_case->delta);
        if (recovered_rtk[lane] != actual_rtk[lane]) {
            return fail("known-fault recovery did not reproduce RTK[31]");
        }
    }

    {
        const double empirical_rate =
            (double)stats.ineffective_count /
            (double)stats.total_queries;

        if ((empirical_rate < 0.25) || (empirical_rate > 0.50)) {
            return fail(
                "empirical ineffective rate is outside the expected interval"
            );
        }

        printf("case delta=0x%02x fault_xor=0x%02x queries=%" PRIu64
               " rate=%.6f RTK[31]=",
               test_case->delta,
               test_case->fault_xor,
               stats.total_queries,
               empirical_rate);
    }

    for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
        printf("%02x", recovered_rtk[lane]);
    }
    fputc('\n', stdout);
    return 0;
}

int main(void)
{
    static const scenario1_case cases[] = {
        { UINT8_C(0x00), UINT8_C(0x01),
          UINT64_C(0x6A09E667F3BCC909) },
        { UINT8_C(0x5a), UINT8_C(0x80),
          UINT64_C(0xBB67AE8584CAA73B) },
        { UINT8_C(0xff), UINT8_C(0x5a),
          UINT64_C(0x3C6EF372FE94F82B) }
    };
    uint8_t key[KEY_BYTES];
    uint8_t tweak[TWEAK_BYTES];

    for (size_t index = 0U; index < KEY_BYTES; ++index) {
        key[index] = (uint8_t)index;
    }
    for (size_t index = 0U; index < TWEAK_BYTES; ++index) {
        tweak[index] = (uint8_t)index;
    }

    for (size_t index = 0U;
         index < sizeof(cases) / sizeof(cases[0]);
         ++index) {
        if (run_case(key, tweak, &cases[index]) != 0) {
            lilliput_fault_reset();
            return 1;
        }
    }

    lilliput_fault_reset();
    puts("PASS: Scenario 1 verified for zero/nonzero fault inputs and multiple faulty outputs.");
    return 0;
}
