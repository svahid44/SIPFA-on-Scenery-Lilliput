#include "detection_dataset.h"
#include "infection_dataset.h"
#include "known_detection_attack.h"
#include "persistent_fault.h"
#include "scenery.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define DEFAULT_SAMPLES_PER_SBOX UINT64_C(32768)
#define DEFAULT_SEED UINT64_C(0x13198A2E03707344)

struct writer_context {
    FILE *file;
    uint8_t target_sbox;
};

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
    struct writer_context *context = (struct writer_context *)user_data;

    if (context == NULL || context->file == NULL) {
        return -1;
    }
    fprintf(context->file, "%u,%" PRIu64 ",", context->target_sbox,
            sample_index);
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
    const uint8_t delta = 0x5u;
    const uint8_t correct_output = scenery_sbox_correct(delta);
    const uint8_t faulty_output = (uint8_t)((correct_output + 1u) & 0x0Fu);
    uint64_t samples_per_sbox = DEFAULT_SAMPLES_PER_SBOX;
    uint64_t base_seed = DEFAULT_SEED;
    scenery_ctx ctx;
    scenery_infection_stats per_sbox_stats[SCENERY_ATTACK_SBOXES];
    FILE *dataset_file;
    FILE *summary_file;
    uint64_t total_published = 0u;
    uint64_t total_ineffective = 0u;
    uint64_t total_infected = 0u;
    size_t sbox;

    if ((argc > 1 && parse_u64(argv[1], &samples_per_sbox) != 0) ||
        (argc > 2 && parse_u64(argv[2], &base_seed) != 0) ||
        argc > 3 || samples_per_sbox == 0u) {
        fprintf(stderr, "Usage: %s [samples_per_sbox] [base_seed]\n", argv[0]);
        return 2;
    }

    if (scenery_init(&ctx, key) != 0) {
        fputs("FAIL: scenery_init failed.\n", stderr);
        return 1;
    }

    dataset_file = fopen("results/scenario3_all_sboxes_infection_ciphertexts.csv",
                         "w");
    if (dataset_file == NULL) {
        perror("results/scenario3_all_sboxes_infection_ciphertexts.csv");
        return 1;
    }
    fputs("target_sbox,sample_index,ciphertext\n", dataset_file);

    for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
        const uint64_t seed = base_seed +
            UINT64_C(0x9E3779B97F4A7C15) * (uint64_t)(sbox + 1u);
        struct writer_context writer;
        int status;

        scenery_fault_reset();
        if (scenery_fault_inject((uint8_t)sbox, delta, faulty_output) != 0) {
            fprintf(stderr, "FAIL: fault injection failed for S-box %zu.\n", sbox);
            fclose(dataset_file);
            return 1;
        }

        writer.file = dataset_file;
        writer.target_sbox = (uint8_t)sbox;
        status = scenery_infection_collect(
            &ctx,
            samples_per_sbox,
            seed,
            &per_sbox_stats[sbox],
            write_public_sample,
            &writer
        );
        if (status != 0) {
            fprintf(stderr,
                    "FAIL: infection collector returned %d for S-box %zu.\n",
                    status,
                    sbox);
            fclose(dataset_file);
            scenery_fault_reset();
            return 1;
        }

        total_published += per_sbox_stats[sbox].published_count;
        total_ineffective += per_sbox_stats[sbox].internal_ineffective_count;
        total_infected += per_sbox_stats[sbox].internal_effective_count;

        printf("S-box %zu: published=%" PRIu64
               ", ineffective=%" PRIu64
               ", infected=%" PRIu64
               ", rate=%.9f\n",
               sbox,
               per_sbox_stats[sbox].published_count,
               per_sbox_stats[sbox].internal_ineffective_count,
               per_sbox_stats[sbox].internal_effective_count,
               (double)per_sbox_stats[sbox].internal_ineffective_count /
               (double)per_sbox_stats[sbox].published_count);
    }

    scenery_fault_reset();
    if (fclose(dataset_file) != 0) {
        perror("closing all-S-box infection dataset");
        return 1;
    }

    summary_file = fopen(
        "results/scenario3_all_sboxes_infection_collection_summary.csv",
        "w"
    );
    if (summary_file == NULL) {
        perror("results/scenario3_all_sboxes_infection_collection_summary.csv");
        return 1;
    }
    fputs("target_sbox,known_delta,seed,published_count,internal_ineffective_count,"
          "internal_infected_count,empirical_ineffective_rate\n", summary_file);
    for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
        const uint64_t seed = base_seed +
            UINT64_C(0x9E3779B97F4A7C15) * (uint64_t)(sbox + 1u);
        fprintf(summary_file,
                "%zu,0x%X,0x%016" PRIX64 ",%" PRIu64 ",%" PRIu64
                ",%" PRIu64 ",%.12f\n",
                sbox,
                delta,
                seed,
                per_sbox_stats[sbox].published_count,
                per_sbox_stats[sbox].internal_ineffective_count,
                per_sbox_stats[sbox].internal_effective_count,
                (double)per_sbox_stats[sbox].internal_ineffective_count /
                (double)per_sbox_stats[sbox].published_count);
    }
    fprintf(summary_file,
            "aggregate,0x%X,0x%016" PRIX64 ",%" PRIu64 ",%" PRIu64
            ",%" PRIu64 ",%.12f\n",
            delta,
            base_seed,
            total_published,
            total_ineffective,
            total_infected,
            (double)total_ineffective / (double)total_published);
    if (fclose(summary_file) != 0) {
        perror("closing all-S-box infection summary");
        return 1;
    }

    puts("Scenario 3 / Step 2A: eight known-fault infection campaigns");
    printf("known delta:               0x%X\n", delta);
    printf("correct S-box output:      0x%X\n", correct_output);
    printf("faulty S-box output:       0x%X\n", faulty_output);
    printf("published per S-box:       %" PRIu64 "\n", samples_per_sbox);
    printf("total public outputs:      %" PRIu64 "\n", total_published);
    printf("total internal ineffective:%" PRIu64 "\n", total_ineffective);
    printf("total infected outputs:    %" PRIu64 "\n", total_infected);
    printf("theoretical ineffective rate: %.9f\n",
           scenery_detection_theoretical_ineffective_rate());
    printf("aggregate empirical rate:    %.9f\n",
           (double)total_ineffective / (double)total_published);
    puts("dataset: results/scenario3_all_sboxes_infection_ciphertexts.csv");
    puts("summary: results/scenario3_all_sboxes_infection_collection_summary.csv");
    puts("PASS: eight independent infection datasets were published without labels.");
    return 0;
}
