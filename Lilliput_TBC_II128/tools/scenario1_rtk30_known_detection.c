#include <errno.h>
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

#define DEFAULT_TARGET UINT64_C(5000)
#define DEFAULT_MAX_QUERIES UINT64_C(120000)
#define DEFAULT_SEED UINT64_C(0x13198A2E03707344)

typedef struct collection_context {
    FILE *samples_file;
    uint8_t *ciphertexts;
    size_t capacity;
    size_t count;
} collection_context;

static void print_hex(FILE *stream, const uint8_t *data, size_t length)
{
    for (size_t index = 0U; index < length; ++index) {
        fprintf(stream, "%02x", data[index]);
    }
}

static int parse_u64(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    errno = 0;
    parsed = strtoull(text, &end, 0);
    if ((errno != 0) || (end == text) || (*end != '\0')) {
        return -1;
    }

    *value = (uint64_t)parsed;
    return 0;
}

static int parse_u8(const char *text, uint8_t *value)
{
    uint64_t parsed;

    if ((parse_u64(text, &parsed) != 0) || (parsed > UINT8_MAX)) {
        return -1;
    }
    *value = (uint8_t)parsed;
    return 0;
}

static int retain_ciphertext(
    uint64_t query_index,
    uint64_t ineffective_index,
    const uint8_t ciphertext[BLOCK_BYTES],
    void *user_data
)
{
    collection_context *context = user_data;

    if ((context == NULL) || (context->ciphertexts == NULL) ||
        (context->count >= context->capacity)) {
        return -1;
    }

    memcpy(context->ciphertexts + context->count * BLOCK_BYTES,
           ciphertext,
           BLOCK_BYTES);
    ++context->count;

    if (context->samples_file != NULL) {
        fprintf(context->samples_file,
                "%" PRIu64 ",%" PRIu64 ",",
                query_index,
                ineffective_index);
        print_hex(context->samples_file, ciphertext, BLOCK_BYTES);
        fputc('\n', context->samples_file);
        if (ferror(context->samples_file)) {
            return -1;
        }
    }

    return 0;
}

static int write_summary(
    const char *path,
    const lilliput_known_detection_iterative_result *result,
    const uint8_t actual_rtk31[ROUND_TWEAKEY_BYTES],
    const uint8_t actual_rtk30[ROUND_TWEAKEY_BYTES]
)
{
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        return -1;
    }

    fputs("round,lane,missing_count,missing_value,recovered_rtk,actual_rtk,status\n",
          file);
    for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
        fprintf(file,
                "31,%zu,%zu,0x%02x,0x%02x,0x%02x,%s\n",
                lane,
                result->final_missing_count[lane],
                result->final_missing_value[lane],
                result->recovered_rtk31[lane],
                actual_rtk31[lane],
                (result->final_missing_count[lane] == 1U &&
                 result->recovered_rtk31[lane] == actual_rtk31[lane])
                    ? "PASS" : "FAIL");
    }
    for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
        fprintf(file,
                "30,%zu,%zu,0x%02x,0x%02x,0x%02x,%s\n",
                lane,
                result->penultimate_missing_count[lane],
                result->penultimate_missing_value[lane],
                result->recovered_rtk30[lane],
                actual_rtk30[lane],
                (result->penultimate_missing_count[lane] == 1U &&
                 result->recovered_rtk30[lane] == actual_rtk30[lane])
                    ? "PASS" : "FAIL");
    }

    if (fclose(file) != 0) {
        perror(path);
        return -1;
    }
    return 0;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s [target_ineffective] [fault_input] [seed] "
            "[samples.csv] [summary.csv]\n",
            program);
}

int main(int argc, char **argv)
{
    uint64_t target = DEFAULT_TARGET;
    uint64_t seed = DEFAULT_SEED;
    uint8_t delta = UINT8_C(0x00);
    const char *samples_path = "results/scenario1_rtk30_samples.csv";
    const char *summary_path = "results/scenario1_rtk30_summary.csv";
    uint8_t key[KEY_BYTES];
    uint8_t tweak[TWEAK_BYTES];
    uint8_t actual_rtk31[ROUND_TWEAKEY_BYTES];
    uint8_t actual_rtk30[ROUND_TWEAKEY_BYTES];
    uint8_t *ciphertexts = NULL;
    FILE *samples_file = NULL;
    collection_context context;
    lilliput_detection_stats stats;
    lilliput_known_detection_iterative_result result;
    int recovery_status;
    int success = 1;

    if ((argc > 1) && (parse_u64(argv[1], &target) != 0)) {
        usage(argv[0]);
        return 2;
    }
    if ((argc > 2) && (parse_u8(argv[2], &delta) != 0)) {
        usage(argv[0]);
        return 2;
    }
    if ((argc > 3) && (parse_u64(argv[3], &seed) != 0)) {
        usage(argv[0]);
        return 2;
    }
    if (argc > 4) {
        samples_path = argv[4];
    }
    if (argc > 5) {
        summary_path = argv[5];
    }
    if ((argc > 6) || (target == 0U) ||
        (target > (uint64_t)(SIZE_MAX / BLOCK_BYTES))) {
        usage(argv[0]);
        return 2;
    }

    for (size_t index = 0U; index < KEY_BYTES; ++index) {
        key[index] = (uint8_t)index;
        tweak[index] = (uint8_t)index;
    }

    ciphertexts = malloc((size_t)target * BLOCK_BYTES);
    if (ciphertexts == NULL) {
        fputs("could not allocate accepted-ciphertext buffer\n", stderr);
        return 1;
    }

    samples_file = fopen(samples_path, "w");
    if (samples_file == NULL) {
        perror(samples_path);
        free(ciphertexts);
        return 1;
    }
    fputs("query_index,ineffective_index,ciphertext\n", samples_file);

    context.samples_file = samples_file;
    context.ciphertexts = ciphertexts;
    context.capacity = (size_t)target;
    context.count = 0U;

    lilliput_fault_reset();
    if (lilliput_fault_inject(
            delta,
            (uint8_t)(lilliput_sbox_correct(delta) ^ UINT8_C(0x01))) != 0) {
        fputs("persistent fault injection failed\n", stderr);
        fclose(samples_file);
        free(ciphertexts);
        return 1;
    }

    {
        uint64_t max_queries = DEFAULT_MAX_QUERIES;
        int collection_status;

        if (target > DEFAULT_MAX_QUERIES / 4U) {
            if (target > UINT64_MAX / 4U) {
                fclose(samples_file);
                free(ciphertexts);
                fputs("target is too large\n", stderr);
                return 2;
            }
            max_queries = target * 4U;
        }

        collection_status = lilliput_detection_collect(
            key,
            tweak,
            target,
            max_queries,
            seed,
            &stats,
            retain_ciphertext,
            &context
        );
        if (fclose(samples_file) != 0) {
            perror(samples_path);
            free(ciphertexts);
            return 1;
        }
        samples_file = NULL;

        if ((collection_status != 0) ||
            (context.count != (size_t)target)) {
            fprintf(stderr,
                    "dataset collection failed: status=%d retained=%zu\n",
                    collection_status,
                    context.count);
            free(ciphertexts);
            return 1;
        }
    }

    recovery_status = lilliput_known_detection_recover_last_two_rtks(
        ciphertexts,
        context.count,
        delta,
        &result
    );
    if (recovery_status != 0) {
        fprintf(stderr,
                "Algorithm-1 iterative recovery failed with status %d\n",
                recovery_status);
        free(ciphertexts);
        lilliput_fault_reset();
        return 1;
    }

    if ((lilliput_reference_round_tweakey(
             key, tweak, ROUNDS - 1U, actual_rtk31) != 0) ||
        (lilliput_reference_round_tweakey(
             key, tweak, ROUNDS - 2U, actual_rtk30) != 0)) {
        free(ciphertexts);
        lilliput_fault_reset();
        fputs("validation RTK derivation failed\n", stderr);
        return 1;
    }

    if ((memcmp(result.recovered_rtk31,
                actual_rtk31,
                ROUND_TWEAKEY_BYTES) != 0) ||
        (memcmp(result.recovered_rtk30,
                actual_rtk30,
                ROUND_TWEAKEY_BYTES) != 0)) {
        success = 0;
    }

    if (write_summary(
            summary_path,
            &result,
            actual_rtk31,
            actual_rtk30) != 0) {
        free(ciphertexts);
        lilliput_fault_reset();
        return 1;
    }

    printf("queries:              %" PRIu64 "\n", stats.total_queries);
    printf("ineffective samples:  %" PRIu64 "\n", stats.ineffective_count);
    printf("effective samples:    %" PRIu64 "\n", stats.effective_count);
    printf("ineffective rate:      %.6f\n",
           (double)stats.ineffective_count / (double)stats.total_queries);
    printf("fault input delta:     0x%02x\n", delta);
    fputs("recovered RTK[31]:     ", stdout);
    print_hex(stdout, result.recovered_rtk31, ROUND_TWEAKEY_BYTES);
    fputc('\n', stdout);
    fputs("actual RTK[31]:        ", stdout);
    print_hex(stdout, actual_rtk31, ROUND_TWEAKEY_BYTES);
    fputc('\n', stdout);
    fputs("recovered RTK[30]:     ", stdout);
    print_hex(stdout, result.recovered_rtk30, ROUND_TWEAKEY_BYTES);
    fputc('\n', stdout);
    fputs("actual RTK[30]:        ", stdout);
    print_hex(stdout, actual_rtk30, ROUND_TWEAKEY_BYTES);
    fputc('\n', stdout);
    printf("samples CSV:           %s\n", samples_path);
    printf("summary CSV:           %s\n", summary_path);

    free(ciphertexts);
    lilliput_fault_reset();

    if (!success) {
        fputs("FAIL: recovered RTKs do not match validation values\n", stderr);
        return 1;
    }

    puts("PASS: Scenario 1 recovered RTK[31] and RTK[30] exactly as in SIPFA Algorithm 1.");
    return 0;
}
