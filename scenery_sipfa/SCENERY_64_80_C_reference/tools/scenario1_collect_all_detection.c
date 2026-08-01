#include "detection_dataset.h"
#include "persistent_fault.h"
#include "scenery.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define DEFAULT_TARGET      UINT64_C(4096)
#define DEFAULT_MAX_QUERIES UINT64_C(50000)
#define DEFAULT_BASE_SEED   UINT64_C(0x6A09E667F3BCC909)
#define DATASET_PATH "results/scenario1_all_sboxes_ineffective.csv"
#define SUMMARY_PATH "results/scenario1_all_sboxes_detection_summary.csv"

typedef struct writer_context {
    FILE *file;
    uint8_t target_sbox;
} writer_context;

static void print_hex(FILE *file, const uint8_t *data, size_t length)
{
    size_t index;
    for (index = 0u; index < length; ++index) {
        fprintf(file, "%02X", data[index]);
    }
}

static int write_sample(
    uint64_t query_index,
    uint64_t ineffective_index,
    const uint8_t plaintext[SCENERY_BLOCK_SIZE],
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    void *user_data
)
{
    writer_context *context = (writer_context *)user_data;

    if (context == NULL || context->file == NULL) {
        return -1;
    }
    fprintf(context->file, "%u,%" PRIu64 ",%" PRIu64 ",",
            context->target_sbox, query_index, ineffective_index);
    print_hex(context->file, plaintext, SCENERY_BLOCK_SIZE);
    fputc(',', context->file);
    print_hex(context->file, ciphertext, SCENERY_BLOCK_SIZE);
    fputc('\n', context->file);
    return ferror(context->file) ? -1 : 0;
}

static int parse_u64(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    errno = 0;
    parsed = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0') {
        return -1;
    }
    *value = (uint64_t)parsed;
    return 0;
}

int main(int argc, char **argv)
{
    const uint8_t key[SCENERY_KEY_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99
    };
    const uint8_t known_delta = 0x5u;
    const uint8_t correct_output = scenery_sbox_correct(known_delta);
    const uint8_t faulty_output = (uint8_t)(
        (correct_output + 1u) & 0x0Fu
    );
    uint64_t target = DEFAULT_TARGET;
    uint64_t max_queries = DEFAULT_MAX_QUERIES;
    uint64_t base_seed = DEFAULT_BASE_SEED;
    scenery_ctx ctx;
    scenery_detection_stats stats[SCENERY_LOGICAL_SBOXES];
    FILE *dataset_file;
    FILE *summary_file;
    uint64_t total_queries = 0u;
    uint64_t total_effective = 0u;
    size_t sbox;

    if ((argc > 1 && parse_u64(argv[1], &target) != 0) ||
        (argc > 2 && parse_u64(argv[2], &max_queries) != 0) ||
        (argc > 3 && parse_u64(argv[3], &base_seed) != 0) ||
        argc > 4 || target == 0u || max_queries < target) {
        fprintf(stderr,
                "Usage: %s [ineffective_per_sbox] [max_queries_per_sbox] [base_seed]\n",
                argv[0]);
        return 2;
    }

    if (scenery_init(&ctx, key) != 0) {
        fputs("FAIL: scenery_init failed.\n", stderr);
        return 1;
    }

    dataset_file = fopen(DATASET_PATH, "w");
    if (dataset_file == NULL) {
        perror(DATASET_PATH);
        return 1;
    }
    fputs("target_sbox,query_index,ineffective_index,plaintext,ciphertext\n",
          dataset_file);

    summary_file = fopen(SUMMARY_PATH, "w");
    if (summary_file == NULL) {
        perror(SUMMARY_PATH);
        fclose(dataset_file);
        return 1;
    }
    fputs("target_sbox,known_delta,seed,target_ineffective,total_queries,"
          "ineffective_count,effective_count,theoretical_rate,empirical_rate,"
          "absolute_error\n", summary_file);

    for (sbox = 0u; sbox < SCENERY_LOGICAL_SBOXES; ++sbox) {
        writer_context context;
        const uint64_t seed = base_seed ^
            (UINT64_C(0x9E3779B97F4A7C15) * (uint64_t)(sbox + 1u));
        const double theoretical_rate =
            scenery_detection_theoretical_ineffective_rate();
        double empirical_rate;
        double absolute_error;
        int status;

        scenery_fault_reset();
        if (scenery_fault_inject(
                (uint8_t)sbox,
                known_delta,
                faulty_output) != 0) {
            fputs("FAIL: fault injection failed.\n", stderr);
            fclose(dataset_file);
            fclose(summary_file);
            return 1;
        }

        context.file = dataset_file;
        context.target_sbox = (uint8_t)sbox;
        status = scenery_detection_collect(
            &ctx,
            target,
            max_queries,
            seed,
            &stats[sbox],
            write_sample,
            &context
        );
        if (status != 0) {
            fprintf(stderr,
                    "FAIL: campaign for S-box %zu returned %d.\n",
                    sbox, status);
            fclose(dataset_file);
            fclose(summary_file);
            scenery_fault_reset();
            return 1;
        }

        empirical_rate = (double)stats[sbox].ineffective_count /
            (double)stats[sbox].total_queries;
        absolute_error = empirical_rate >= theoretical_rate
            ? empirical_rate - theoretical_rate
            : theoretical_rate - empirical_rate;

        fprintf(summary_file,
                "%zu,0x%X,0x%016" PRIX64 ",%" PRIu64 ",%" PRIu64
                ",%" PRIu64 ",%" PRIu64 ",%.12f,%.12f,%.12f\n",
                sbox, known_delta, seed, target,
                stats[sbox].total_queries,
                stats[sbox].ineffective_count,
                stats[sbox].effective_count,
                theoretical_rate,
                empirical_rate,
                absolute_error);

        total_queries += stats[sbox].total_queries;
        total_effective += stats[sbox].effective_count;
        printf("S-box %zu: ineffective=%" PRIu64
               ", queries=%" PRIu64 ", rate=%.9f\n",
               sbox,
               stats[sbox].ineffective_count,
               stats[sbox].total_queries,
               empirical_rate);
    }

    scenery_fault_reset();
    if (fclose(dataset_file) != 0 || fclose(summary_file) != 0) {
        fputs("FAIL: closing an output CSV failed.\n", stderr);
        return 1;
    }

    puts("Scenario 1 / Step 4A: eight detection-based campaigns");
    printf("known delta:               0x%X\n", known_delta);
    printf("correct S-box output:      0x%X\n", correct_output);
    printf("faulty S-box output:       0x%X\n", faulty_output);
    printf("ineffective per S-box:     %" PRIu64 "\n", target);
    printf("total ineffective outputs: %" PRIu64 "\n",
           target * SCENERY_LOGICAL_SBOXES);
    printf("total oracle queries:      %" PRIu64 "\n", total_queries);
    printf("total effective blocked:   %" PRIu64 "\n", total_effective);
    printf("dataset:                   %s\n", DATASET_PATH);
    printf("summary:                   %s\n", SUMMARY_PATH);
    puts("PASS: eight independent ineffective datasets were collected.");
    return 0;
}
