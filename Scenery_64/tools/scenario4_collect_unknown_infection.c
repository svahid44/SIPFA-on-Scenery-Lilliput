#include "detection_dataset.h"
#include "infection_dataset.h"
#include "persistent_fault.h"
#include "scenery.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define DEFAULT_SAMPLES UINT64_C(65536)
#define DEFAULT_SEED UINT64_C(0x6A09E667F3BCC909)
#define DEFAULT_SECRET_SBOX UINT8_C(5)
#define DEFAULT_SECRET_DELTA UINT8_C(0xB)

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
    uint64_t total_samples = DEFAULT_SAMPLES;
    uint64_t seed = DEFAULT_SEED;
    uint64_t parsed_sbox = DEFAULT_SECRET_SBOX;
    uint64_t parsed_delta = DEFAULT_SECRET_DELTA;
    uint8_t secret_sbox;
    uint8_t secret_delta;
    uint8_t correct_output;
    uint8_t faulty_output;
    scenery_ctx ctx;
    scenery_infection_stats stats;
    FILE *dataset_file;
    FILE *summary_file;
    double empirical_rate;
    int status;

    if ((argc > 1 && parse_u64(argv[1], &total_samples) != 0) ||
        (argc > 2 && parse_u64(argv[2], &seed) != 0) ||
        (argc > 3 && parse_u64(argv[3], &parsed_sbox) != 0) ||
        (argc > 4 && parse_u64(argv[4], &parsed_delta) != 0) ||
        argc > 5 || total_samples == 0u || parsed_sbox >= 8u ||
        parsed_delta >= 16u) {
        fprintf(stderr,
                "Usage: %s [samples] [seed] [secret_sbox] [secret_delta]\n",
                argv[0]);
        return 2;
    }

    secret_sbox = (uint8_t)parsed_sbox;
    secret_delta = (uint8_t)parsed_delta;
    correct_output = scenery_sbox_correct(secret_delta);
    faulty_output = (uint8_t)((correct_output + 1u) & 0x0Fu);

    if (scenery_init(&ctx, key) != 0) {
        fputs("FAIL: scenery_init failed.\n", stderr);
        return 1;
    }
    scenery_fault_reset();
    if (scenery_fault_inject(
            secret_sbox,
            secret_delta,
            faulty_output) != 0) {
        fputs("FAIL: persistent fault injection failed.\n", stderr);
        return 1;
    }

    dataset_file = fopen(
        "results/scenario4_unknown_infection_ciphertexts.csv",
        "w"
    );
    if (dataset_file == NULL) {
        perror("results/scenario4_unknown_infection_ciphertexts.csv");
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
        perror("closing scenario4 public dataset");
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
        "results/scenario4_unknown_infection_generation_summary.csv",
        "w"
    );
    if (summary_file == NULL) {
        perror("results/scenario4_unknown_infection_generation_summary.csv");
        scenery_fault_reset();
        return 1;
    }
    fputs("parameter,value\n", summary_file);
    fprintf(summary_file, "secret_sbox,%u\n", secret_sbox);
    fprintf(summary_file, "secret_delta,0x%X\n", secret_delta);
    fprintf(summary_file, "correct_sbox_output,0x%X\n", correct_output);
    fprintf(summary_file, "faulty_sbox_output,0x%X\n", faulty_output);
    fprintf(summary_file, "seed,0x%016" PRIX64 "\n", seed);
    fprintf(summary_file, "published_count,%" PRIu64 "\n",
            stats.published_count);
    fprintf(summary_file, "internal_ineffective_count,%" PRIu64 "\n",
            stats.internal_ineffective_count);
    fprintf(summary_file, "internal_infected_count,%" PRIu64 "\n",
            stats.internal_effective_count);
    fprintf(summary_file, "theoretical_ineffective_rate,%.12f\n",
            scenery_detection_theoretical_ineffective_rate());
    fprintf(summary_file, "empirical_ineffective_rate,%.12f\n",
            empirical_rate);
    fclose(summary_file);

    puts("Scenario 4 / Step 1A: collect unlabeled infection-based outputs");
    printf("secret logical S-box:        %u\n", secret_sbox);
    printf("secret delta:                0x%X\n", secret_delta);
    printf("correct/faulty S-box output: 0x%X -> 0x%X\n",
           correct_output,
           faulty_output);
    printf("seed:                        0x%016" PRIX64 "\n", seed);
    printf("published outputs:           %" PRIu64 "\n",
           stats.published_count);
    printf("internal ineffective:        %" PRIu64 "\n",
           stats.internal_ineffective_count);
    printf("internal infected:           %" PRIu64 "\n",
           stats.internal_effective_count);
    printf("theoretical ineffective rate: %.9f\n",
           scenery_detection_theoretical_ineffective_rate());
    printf("empirical ineffective rate:   %.9f\n", empirical_rate);
    puts("public dataset: results/scenario4_unknown_infection_ciphertexts.csv");
    puts("simulation-only summary: results/scenario4_unknown_infection_generation_summary.csv");

    scenery_fault_reset();
    puts("PASS: every query produced one unlabeled public ciphertext.");
    return 0;
}
