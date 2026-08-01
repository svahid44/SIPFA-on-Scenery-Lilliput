#include <errno.h>
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

#define DEFAULT_TARGET UINT64_C(4000)
#define DEFAULT_MAX_QUERIES UINT64_C(100000)
#define DEFAULT_SEED UINT64_C(0x3C6EF372FE94F82B)
#define DEFAULT_SECRET_DELTA UINT8_C(0x5a)

struct dataset_context {
    FILE *file;
    uint8_t *ciphertexts;
    size_t capacity;
};

static void print_hex(FILE *stream, const uint8_t *data, size_t length)
{
    for (size_t i = 0; i < length; ++i) {
        fprintf(stream, "%02x", data[i]);
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

static int capture_sample(
    uint64_t query_index,
    uint64_t ineffective_index,
    const uint8_t ciphertext[BLOCK_BYTES],
    void *user_data
)
{
    struct dataset_context *context = user_data;
    size_t index;

    if ((context == NULL) || (context->file == NULL) ||
        (ineffective_index == 0U) ||
        (ineffective_index > context->capacity)) {
        return -1;
    }

    index = (size_t)(ineffective_index - 1U);
    memcpy(context->ciphertexts + index * BLOCK_BYTES, ciphertext, BLOCK_BYTES);

    fprintf(context->file, "%" PRIu64 ",%" PRIu64 ",",
            query_index, ineffective_index);
    print_hex(context->file, ciphertext, BLOCK_BYTES);
    fputc('\n', context->file);

    return ferror(context->file) ? -1 : 0;
}

static int write_final_histogram(
    const char *path,
    const lilliput_detection_stats *stats
)
{
    FILE *file = fopen(path, "w");
    if (file == NULL) {
        perror(path);
        return -1;
    }

    fputs("lane,value,count,is_missing\n", file);
    for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
        for (size_t value = 0; value < LILLIPUT_SBOX_DOMAIN; ++value) {
            fprintf(file,
                    "%zu,%zu,%" PRIu64 ",%u\n",
                    lane,
                    value,
                    stats->histogram[lane][value],
                    stats->histogram[lane][value] == 0U ? 1U : 0U);
        }
    }

    if (fclose(file) != 0) {
        perror(path);
        return -1;
    }
    return 0;
}

static int write_candidate_csv(
    const char *path,
    const lilliput_unknown_detection_result *result
)
{
    FILE *file = fopen(path, "w");
    if (file == NULL) {
        perror(path);
        return -1;
    }

    fputs("delta_candidate,survives", file);
    for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
        fprintf(file, ",lane%zu_missing_count", lane);
    }
    fputc('\n', file);

    for (size_t delta = 0; delta < LILLIPUT_UNKNOWN_DELTA_CANDIDATES; ++delta) {
        int survives = 1;
        for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
            if (result->previous_round_missing_count[delta][lane] == 0U) {
                survives = 0;
            }
        }

        fprintf(file, "%zu,%d", delta, survives);
        for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
            fprintf(file,
                    ",%u",
                    (unsigned int)result->previous_round_missing_count[delta][lane]);
        }
        fputc('\n', file);
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
            "Usage: %s [target_ineffective] [secret_fault_input] [seed] "
            "[samples.csv] [histogram.csv] [candidates.csv]\n",
            program);
}

int main(int argc, char **argv)
{
    uint64_t target = DEFAULT_TARGET;
    uint64_t seed = DEFAULT_SEED;
    uint8_t secret_delta = DEFAULT_SECRET_DELTA;
    const char *samples_path = "results/scenario2_ineffective_samples.csv";
    const char *histogram_path = "results/scenario2_final_histogram.csv";
    const char *candidate_path = "results/scenario2_candidates.csv";
    uint8_t key[KEY_BYTES];
    uint8_t tweak[TWEAK_BYTES];
    uint8_t actual_rtk[ROUND_TWEAKEY_BYTES];
    uint8_t *ciphertexts = NULL;
    lilliput_detection_stats stats;
    lilliput_unknown_detection_result result;
    struct dataset_context context;
    uint64_t max_queries = DEFAULT_MAX_QUERIES;
    int status;

    if ((argc > 1) && (parse_u64(argv[1], &target) != 0)) {
        usage(argv[0]);
        return 2;
    }
    if ((argc > 2) && (parse_u8(argv[2], &secret_delta) != 0)) {
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
        histogram_path = argv[5];
    }
    if (argc > 6) {
        candidate_path = argv[6];
    }
    if (argc > 7) {
        usage(argv[0]);
        return 2;
    }
    if ((target == 0U) || (target > (uint64_t)(SIZE_MAX / BLOCK_BYTES))) {
        fputs("invalid target_ineffective\n", stderr);
        return 2;
    }
    if (target > DEFAULT_MAX_QUERIES / 4U) {
        if (target > UINT64_MAX / 4U) {
            fputs("target is too large\n", stderr);
            return 2;
        }
        max_queries = target * 4U;
    }

    for (size_t i = 0; i < KEY_BYTES; ++i) {
        key[i] = (uint8_t)i;
    }
    for (size_t i = 0; i < TWEAK_BYTES; ++i) {
        tweak[i] = (uint8_t)i;
    }

    ciphertexts = malloc((size_t)target * BLOCK_BYTES);
    if (ciphertexts == NULL) {
        fputs("could not allocate ciphertext dataset\n", stderr);
        return 1;
    }

    context.file = fopen(samples_path, "w");
    if (context.file == NULL) {
        perror(samples_path);
        free(ciphertexts);
        return 1;
    }
    context.ciphertexts = ciphertexts;
    context.capacity = (size_t)target;
    fputs("query_index,ineffective_index,ciphertext\n", context.file);

    lilliput_fault_reset();
    status = lilliput_fault_inject(
        secret_delta,
        (uint8_t)(lilliput_sbox_correct(secret_delta) ^ UINT8_C(0x01))
    );
    if (status != 0) {
        fclose(context.file);
        free(ciphertexts);
        fputs("persistent fault injection failed\n", stderr);
        return 1;
    }

    status = lilliput_detection_collect(key,
                                        tweak,
                                        target,
                                        max_queries,
                                        seed,
                                        &stats,
                                        capture_sample,
                                        &context);
    if (fclose(context.file) != 0) {
        perror(samples_path);
        free(ciphertexts);
        return 1;
    }
    if (status != 0) {
        fprintf(stderr, "dataset collection failed with status %d\n", status);
        free(ciphertexts);
        return 1;
    }

    /*
     * Attack boundary: only accepted ciphertexts are passed below.
     * The secret fault input, key, tweak, and actual RTK are not arguments.
     */
    status = lilliput_unknown_detection_recover(
        ciphertexts,
        (size_t)stats.ineffective_count,
        &result
    );

    if (write_final_histogram(histogram_path, &stats) != 0) {
        free(ciphertexts);
        return 1;
    }
    if (write_candidate_csv(candidate_path, &result) != 0) {
        free(ciphertexts);
        return 1;
    }

    if (lilliput_reference_round_tweakey(
            key, tweak, ROUNDS - 1U, actual_rtk) != 0) {
        free(ciphertexts);
        fputs("could not compute reference final-round tweakey\n", stderr);
        return 1;
    }

    puts("Scenario 2: unknown-fault, detection-based SIPFA");
    puts("lane  final_missing  relative_RTK_to_lane0");
    for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
        printf("%4zu  0x%02x           0x%02x\n",
               lane,
               result.final_missing[lane],
               result.relative_round_tweakey[lane]);
    }

    printf("\nqueries:                %" PRIu64 "\n", stats.total_queries);
    printf("ineffective samples:    %" PRIu64 "\n", stats.ineffective_count);
    printf("effective samples:      %" PRIu64 "\n", stats.effective_count);
    printf("ineffective rate:        %.6f\n",
           (double)stats.ineffective_count / (double)stats.total_queries);
    printf("initial delta candidates:%u\n",
           (unsigned int)LILLIPUT_UNKNOWN_DELTA_CANDIDATES);
    printf("surviving candidates:   %zu\n", result.surviving_candidate_count);
    printf("samples CSV:            %s\n", samples_path);
    printf("histogram CSV:          %s\n", histogram_path);
    printf("candidates CSV:         %s\n", candidate_path);

    if (status != 0) {
        fprintf(stderr,
                "FAIL: unknown-detection recovery returned %d; survivors=%zu\n",
                status,
                result.surviving_candidate_count);
        lilliput_fault_reset();
        free(ciphertexts);
        return 1;
    }

    printf("recovered fault input:  0x%02x\n", result.recovered_delta);
    printf("actual fault input:     0x%02x\n", secret_delta);
    printf("recovered RTK[31]:      ");
    print_hex(stdout, result.recovered_round_tweakey, ROUND_TWEAKEY_BYTES);
    fputc('\n', stdout);
    printf("actual RTK[31]:         ");
    print_hex(stdout, actual_rtk, ROUND_TWEAKEY_BYTES);
    fputc('\n', stdout);

    lilliput_fault_reset();
    free(ciphertexts);

    if ((result.recovered_delta != secret_delta) ||
        (memcmp(result.recovered_round_tweakey,
                actual_rtk,
                ROUND_TWEAKEY_BYTES) != 0)) {
        fputs("FAIL: recovered values do not match simulation ground truth\n", stderr);
        return 1;
    }

    puts("PASS: Scenario 2 recovered the unknown persistent fault input and complete RTK[31].");
    return 0;
}
