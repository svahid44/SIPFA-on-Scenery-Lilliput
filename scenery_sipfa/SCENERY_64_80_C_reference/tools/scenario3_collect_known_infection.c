#include "detection_dataset.h"
#include "infection_dataset.h"
#include "persistent_fault.h"
#include "scenery.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define DEFAULT_SAMPLES UINT64_C(32768)
#define DEFAULT_SEED UINT64_C(0xA4093822299F31D0)

static void print_hex(FILE *file, const uint8_t *data, size_t length)
{
    size_t index;

    for (index = 0u; index < length; ++index) {
        fprintf(file, "%02X", data[index]);
    }
}

static int write_public_sample(
    uint64_t sample_index,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    void *user_data
)
{
    FILE *file = (FILE *)user_data;

    if (file == NULL) {
        return -1;
    }
    fprintf(file, "%" PRIu64 ",", sample_index);
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
    const uint8_t faulty_output = (uint8_t)((correct_output + 1u) & 0x0Fu);
    uint64_t total_samples = DEFAULT_SAMPLES;
    uint64_t seed = DEFAULT_SEED;
    scenery_ctx ctx;
    scenery_infection_stats stats;
    FILE *dataset_file;
    FILE *summary_file;
    double empirical_rate;
    int status;

    if ((argc > 1 && parse_u64(argv[1], &total_samples) != 0) ||
        (argc > 2 && parse_u64(argv[2], &seed) != 0) ||
        argc > 3 || total_samples == 0u) {
        fprintf(stderr, "Usage: %s [total_samples] [seed]\n", argv[0]);
        return 2;
    }

    if (scenery_init(&ctx, key) != 0) {
        fputs("FAIL: scenery_init failed.\n", stderr);
        return 1;
    }

    scenery_fault_reset();
    if (scenery_fault_inject(target_sbox, delta, faulty_output) != 0) {
        fputs("FAIL: fault injection failed.\n", stderr);
        return 1;
    }

    dataset_file = fopen(
        "results/scenario3_known_infection_ciphertexts.csv",
        "w"
    );
    if (dataset_file == NULL) {
        perror("results/scenario3_known_infection_ciphertexts.csv");
        scenery_fault_reset();
        return 1;
    }
    fputs("sample_index,ciphertext\n", dataset_file);

    status = scenery_infection_collect(
        &ctx,
        total_samples,
        seed,
        &stats,
        write_public_sample,
        dataset_file
    );
    if (fclose(dataset_file) != 0) {
        perror("closing public infection dataset");
        scenery_fault_reset();
        return 1;
    }
    if (status != 0) {
        fprintf(stderr, "FAIL: infection collector returned %d.\n", status);
        scenery_fault_reset();
        return 1;
    }

    empirical_rate = (double)stats.internal_ineffective_count /
                     (double)stats.published_count;

    summary_file = fopen(
        "results/scenario3_known_infection_collection_summary.csv",
        "w"
    );
    if (summary_file == NULL) {
        perror("results/scenario3_known_infection_collection_summary.csv");
        scenery_fault_reset();
        return 1;
    }
    fputs("parameter,value\n", summary_file);
    fprintf(summary_file, "target_sbox,%u\n", target_sbox);
    fprintf(summary_file, "known_delta,0x%X\n", delta);
    fprintf(summary_file, "correct_sbox_output,0x%X\n", correct_output);
    fprintf(summary_file, "faulty_sbox_output,0x%X\n", faulty_output);
    fprintf(summary_file, "seed,0x%016" PRIX64 "\n", seed);
    fprintf(summary_file, "published_count,%" PRIu64 "\n",
            stats.published_count);
    fprintf(summary_file, "internal_ineffective_count,%" PRIu64 "\n",
            stats.internal_ineffective_count);
    fprintf(summary_file, "internal_effective_infected_count,%" PRIu64 "\n",
            stats.internal_effective_count);
    fprintf(summary_file, "theoretical_ineffective_rate,%.12f\n",
            scenery_detection_theoretical_ineffective_rate());
    fprintf(summary_file, "empirical_ineffective_rate,%.12f\n",
            empirical_rate);
    fprintf(summary_file, "public_columns,sample_index|ciphertext\n");
    if (fclose(summary_file) != 0) {
        perror("closing infection summary");
        scenery_fault_reset();
        return 1;
    }

    puts("Scenario 3 / Step 1A: known-fault infection-based public dataset");
    printf("target logical S-box:       %u\n", target_sbox);
    printf("known delta:                0x%X\n", delta);
    printf("correct S-box output:       0x%X\n", correct_output);
    printf("faulty S-box output:        0x%X\n", faulty_output);
    printf("published ciphertexts:      %" PRIu64 "\n", stats.published_count);
    printf("internal ineffective:       %" PRIu64 "\n",
           stats.internal_ineffective_count);
    printf("internal effective/infected: %" PRIu64 "\n",
           stats.internal_effective_count);
    printf("theoretical ineffective rate: %.9f\n",
           scenery_detection_theoretical_ineffective_rate());
    printf("empirical ineffective rate:   %.9f\n", empirical_rate);
    puts("public dataset: results/scenario3_known_infection_ciphertexts.csv");
    puts("simulation summary: results/scenario3_known_infection_collection_summary.csv");

    scenery_fault_reset();
    puts("PASS: every query produced one public output without an event label.");
    return 0;
}
