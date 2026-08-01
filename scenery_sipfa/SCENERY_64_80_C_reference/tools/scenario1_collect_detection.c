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
#define DEFAULT_SEED        UINT64_C(0xBB67AE8584CAA73B)

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
    FILE *file = (FILE *)user_data;

    if (file == NULL) {
        return -1;
    }

    fprintf(file, "%" PRIu64 ",%" PRIu64 ",",
            query_index, ineffective_index);
    print_hex(file, plaintext, SCENERY_BLOCK_SIZE);
    fputc(',', file);
    print_hex(file, ciphertext, SCENERY_BLOCK_SIZE);
    fputc('\n', file);
    return ferror(file) ? -1 : 0;
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
    const uint8_t target_sbox = 3u;
    const uint8_t delta = 0x5u;
    const uint8_t correct_output = scenery_sbox_correct(delta);
    const uint8_t faulty_output =
        (uint8_t)((correct_output + 1u) & 0x0Fu);
    uint64_t target = DEFAULT_TARGET;
    uint64_t max_queries = DEFAULT_MAX_QUERIES;
    uint64_t seed = DEFAULT_SEED;
    scenery_ctx ctx;
    scenery_detection_stats stats;
    FILE *sample_file;
    FILE *summary_file;
    double theoretical_rate;
    double empirical_rate;
    double absolute_error;
    int status;

    if ((argc > 1 && parse_u64(argv[1], &target) != 0) ||
        (argc > 2 && parse_u64(argv[2], &max_queries) != 0) ||
        (argc > 3 && parse_u64(argv[3], &seed) != 0) ||
        argc > 4 || target == 0u || max_queries < target) {
        fprintf(stderr,
                "Usage: %s [target_ineffective] [max_queries] [seed]\n",
                argv[0]);
        return 2;
    }

    if (scenery_init(&ctx, key) != 0) {
        fputs("FAIL: scenery_init failed.\n", stderr);
        return 1;
    }

    scenery_fault_reset();
    if (scenery_fault_inject(
            target_sbox,
            delta,
            faulty_output
        ) != 0) {
        fputs("FAIL: fault injection failed.\n", stderr);
        return 1;
    }

    sample_file = fopen(
        "results/scenario1_detection_ineffective.csv",
        "w"
    );
    if (sample_file == NULL) {
        perror("results/scenario1_detection_ineffective.csv");
        return 1;
    }
    fputs("query_index,ineffective_index,plaintext,ciphertext\n", sample_file);

    status = scenery_detection_collect(
        &ctx,
        target,
        max_queries,
        seed,
        &stats,
        write_sample,
        sample_file
    );
    if (fclose(sample_file) != 0) {
        perror("closing ineffective dataset");
        scenery_fault_reset();
        return 1;
    }

    if (status != 0) {
        fprintf(stderr, "FAIL: dataset collector returned %d.\n", status);
        scenery_fault_reset();
        return 1;
    }

    theoretical_rate = scenery_detection_theoretical_ineffective_rate();
    empirical_rate =
        (double)stats.ineffective_count / (double)stats.total_queries;
    absolute_error = empirical_rate >= theoretical_rate
        ? empirical_rate - theoretical_rate
        : theoretical_rate - empirical_rate;

    summary_file = fopen(
        "results/scenario1_detection_summary.csv",
        "w"
    );
    if (summary_file == NULL) {
        perror("results/scenario1_detection_summary.csv");
        scenery_fault_reset();
        return 1;
    }
    fputs("parameter,value\n", summary_file);
    fprintf(summary_file, "target_sbox,%u\n", target_sbox);
    fprintf(summary_file, "known_delta,0x%X\n", delta);
    fprintf(summary_file, "correct_sbox_output,0x%X\n", correct_output);
    fprintf(summary_file, "faulty_sbox_output,0x%X\n", faulty_output);
    fprintf(summary_file, "seed,0x%016" PRIX64 "\n", seed);
    fprintf(summary_file, "target_ineffective,%" PRIu64 "\n", target);
    fprintf(summary_file, "total_queries,%" PRIu64 "\n", stats.total_queries);
    fprintf(summary_file, "ineffective_count,%" PRIu64 "\n",
            stats.ineffective_count);
    fprintf(summary_file, "effective_count,%" PRIu64 "\n",
            stats.effective_count);
    fprintf(summary_file, "theoretical_rate,%.12f\n", theoretical_rate);
    fprintf(summary_file, "empirical_rate,%.12f\n", empirical_rate);
    fprintf(summary_file, "absolute_error,%.12f\n", absolute_error);
    if (fclose(summary_file) != 0) {
        perror("closing summary");
        scenery_fault_reset();
        return 1;
    }

    puts("Scenario 1 / Step 2: detection-based ineffective dataset");
    printf("target logical S-box:     %u\n", target_sbox);
    printf("known fault input delta:  0x%X\n", delta);
    printf("correct S-box output:     0x%X\n", correct_output);
    printf("faulty S-box output:      0x%X\n", faulty_output);
    printf("target ineffective:       %" PRIu64 "\n", target);
    printf("total oracle queries:     %" PRIu64 "\n", stats.total_queries);
    printf("effective events blocked: %" PRIu64 "\n", stats.effective_count);
    printf("ineffective outputs kept: %" PRIu64 "\n", stats.ineffective_count);
    printf("theoretical rate:         %.9f\n", theoretical_rate);
    printf("empirical rate:           %.9f\n", empirical_rate);
    printf("absolute error:           %.9f\n", absolute_error);
    puts("dataset: results/scenario1_detection_ineffective.csv");
    puts("summary: results/scenario1_detection_summary.csv");

    scenery_fault_reset();
    puts("PASS: only ineffective ciphertexts were released by the detector model.");
    return 0;
}
