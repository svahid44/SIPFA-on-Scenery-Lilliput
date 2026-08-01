#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "detection_dataset.h"
#include "known_detection_iterative.h"
#include "persistent_fault.h"
#include "reference_validation.h"

#define TARGET_INEFFECTIVE UINT64_C(5000)
#define MAX_QUERIES UINT64_C(50000)

typedef struct sample_buffer {
    uint8_t *ciphertexts;
    size_t capacity;
    size_t count;
} sample_buffer;

typedef struct phase3_case {
    uint8_t delta;
    uint8_t fault_xor;
    uint64_t seed;
} phase3_case;

static int retain_ciphertext(
    uint64_t query_index,
    uint64_t ineffective_index,
    const uint8_t ciphertext[BLOCK_BYTES],
    void *user_data
)
{
    sample_buffer *buffer = user_data;

    (void)query_index;
    (void)ineffective_index;

    if ((buffer == NULL) || (buffer->ciphertexts == NULL) ||
        (buffer->count >= buffer->capacity)) {
        return -1;
    }

    memcpy(buffer->ciphertexts + buffer->count * BLOCK_BYTES,
           ciphertext,
           BLOCK_BYTES);
    ++buffer->count;
    return 0;
}

static void print_hex(const uint8_t *data, size_t length)
{
    for (size_t index = 0U; index < length; ++index) {
        printf("%02x", data[index]);
    }
}

static int run_case(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    const phase3_case *test_case
)
{
    uint8_t actual_rtk31[ROUND_TWEAKEY_BYTES];
    uint8_t actual_rtk30[ROUND_TWEAKEY_BYTES];
    uint8_t *ciphertexts = NULL;
    sample_buffer buffer;
    lilliput_detection_stats stats;
    lilliput_known_detection_iterative_result result;
    int status;

    ciphertexts = malloc((size_t)TARGET_INEFFECTIVE * BLOCK_BYTES);
    if (ciphertexts == NULL) {
        fputs("FAIL: sample allocation failed\n", stderr);
        return 1;
    }

    buffer.ciphertexts = ciphertexts;
    buffer.capacity = (size_t)TARGET_INEFFECTIVE;
    buffer.count = 0U;

    lilliput_fault_reset();
    if (lilliput_fault_inject(
            test_case->delta,
            (uint8_t)(lilliput_sbox_correct(test_case->delta) ^
                      test_case->fault_xor)) != 0) {
        free(ciphertexts);
        fputs("FAIL: fault injection failed\n", stderr);
        return 1;
    }

    status = lilliput_detection_collect(
        key,
        tweak,
        TARGET_INEFFECTIVE,
        MAX_QUERIES,
        test_case->seed,
        &stats,
        retain_ciphertext,
        &buffer
    );
    if ((status != 0) || (buffer.count != (size_t)TARGET_INEFFECTIVE)) {
        fprintf(stderr,
                "FAIL: collection status=%d retained=%zu\n",
                status,
                buffer.count);
        free(ciphertexts);
        return 1;
    }

    status = lilliput_known_detection_recover_last_two_rtks(
        ciphertexts,
        buffer.count,
        test_case->delta,
        &result
    );
    if (status != 0) {
        fprintf(stderr, "FAIL: iterative recovery status=%d\n", status);
        free(ciphertexts);
        return 1;
    }

    if ((lilliput_reference_round_tweakey(
             key, tweak, ROUNDS - 1U, actual_rtk31) != 0) ||
        (lilliput_reference_round_tweakey(
             key, tweak, ROUNDS - 2U, actual_rtk30) != 0)) {
        free(ciphertexts);
        fputs("FAIL: validation RTK derivation failed\n", stderr);
        return 1;
    }

    for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
        const uint8_t expected31 =
            (uint8_t)(test_case->delta ^ actual_rtk31[lane]);
        const uint8_t expected30 =
            (uint8_t)(test_case->delta ^ actual_rtk30[lane]);

        if ((result.final_missing_count[lane] != 1U) ||
            (result.final_missing_value[lane] != expected31) ||
            (result.penultimate_missing_count[lane] != 1U) ||
            (result.penultimate_missing_value[lane] != expected30)) {
            fprintf(stderr,
                    "FAIL: lane %zu missing-value relation failed\n",
                    lane);
            free(ciphertexts);
            return 1;
        }
    }

    if ((memcmp(result.recovered_rtk31,
                actual_rtk31,
                ROUND_TWEAKEY_BYTES) != 0) ||
        (memcmp(result.recovered_rtk30,
                actual_rtk30,
                ROUND_TWEAKEY_BYTES) != 0)) {
        free(ciphertexts);
        fputs("FAIL: recovered RTK mismatch\n", stderr);
        return 1;
    }

    printf("delta=0x%02x fault_xor=0x%02x queries=%" PRIu64
           " RTK[31]=",
           test_case->delta,
           test_case->fault_xor,
           stats.total_queries);
    print_hex(result.recovered_rtk31, ROUND_TWEAKEY_BYTES);
    fputs(" RTK[30]=", stdout);
    print_hex(result.recovered_rtk30, ROUND_TWEAKEY_BYTES);
    fputc('\n', stdout);

    free(ciphertexts);
    return 0;
}

int main(void)
{
    {
        uint8_t one_ciphertext[BLOCK_BYTES] = {0};
        lilliput_known_detection_iterative_result invalid_result;

        if ((lilliput_known_detection_recover_last_two_rtks(
                 NULL, 1U, UINT8_C(0x00), &invalid_result) != -1) ||
            (lilliput_known_detection_recover_last_two_rtks(
                 one_ciphertext, 0U, UINT8_C(0x00), &invalid_result) != -1) ||
            (lilliput_known_detection_recover_last_two_rtks(
                 one_ciphertext, 1U, UINT8_C(0x00), &invalid_result) != -2)) {
            fputs("FAIL: iterative recovery status handling is incorrect\n", stderr);
            return 1;
        }
    }

    static const phase3_case cases[] = {
        { UINT8_C(0x00), UINT8_C(0x01), UINT64_C(0x13198A2E03707344) },
        { UINT8_C(0x5a), UINT8_C(0x80), UINT64_C(0xA4093822299F31D0) },
        { UINT8_C(0xff), UINT8_C(0x5a), UINT64_C(0x082EFA98EC4E6C89) }
    };
    uint8_t key[KEY_BYTES];
    uint8_t tweak[TWEAK_BYTES];

    for (size_t index = 0U; index < KEY_BYTES; ++index) {
        key[index] = (uint8_t)index;
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
    puts("PASS: SIPFA Algorithm 1 recovered RTK[31] and RTK[30] from the same accepted-ciphertext dataset.");
    return 0;
}
