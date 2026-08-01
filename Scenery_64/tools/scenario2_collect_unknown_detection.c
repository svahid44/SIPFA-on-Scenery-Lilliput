#include "detection_dataset.h"
#include "known_detection_attack.h"
#include "persistent_fault.h"
#include "scenery.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define DEFAULT_TARGET       UINT64_C(256)
#define DEFAULT_MAX_QUERIES  UINT64_C(10000)
#define DEFAULT_SEED         UINT64_C(0x243F6A8885A308D3)
#define DEFAULT_SECRET_SBOX  5u
#define DEFAULT_SECRET_DELTA 0xBu

static void print_hex(FILE *file, const uint8_t *data, size_t length)
{
    size_t i;

    for (i = 0u; i < length; ++i) {
        fprintf(file, "%02X", data[i]);
    }
}

static int write_public_sample(
    uint64_t query_index,
    uint64_t ineffective_index,
    const uint8_t plaintext[SCENERY_BLOCK_SIZE],
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    void *user_data
)
{
    FILE *file = (FILE *)user_data;

    (void)query_index;
    (void)plaintext;

    if (file == NULL) {
        return -1;
    }
    fprintf(file, "%" PRIu64 ",", ineffective_index);
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

static int parse_u8(const char *text, uint8_t *value)
{
    uint64_t parsed;

    if (parse_u64(text, &parsed) != 0 || parsed > UINT8_MAX) {
        return -1;
    }
    *value = (uint8_t)parsed;
    return 0;
}

int main(int argc, char **argv)
{
    const uint8_t key[SCENERY_KEY_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99
    };
    uint64_t target = DEFAULT_TARGET;
    uint64_t max_queries = DEFAULT_MAX_QUERIES;
    uint64_t seed = DEFAULT_SEED;
    uint8_t secret_sbox = DEFAULT_SECRET_SBOX;
    uint8_t secret_delta = DEFAULT_SECRET_DELTA;
    uint8_t correct_output;
    uint8_t faulty_output;
    uint8_t actual_word;
    uint8_t expected_missing;
    scenery_ctx ctx;
    scenery_detection_stats stats;
    FILE *public_file;
    FILE *public_summary;
    FILE *ground_truth;
    double theoretical_rate;
    double empirical_rate;
    int status;

    if ((argc > 1 && parse_u64(argv[1], &target) != 0) ||
        (argc > 2 && parse_u64(argv[2], &max_queries) != 0) ||
        (argc > 3 && parse_u64(argv[3], &seed) != 0) ||
        (argc > 4 && parse_u8(argv[4], &secret_sbox) != 0) ||
        (argc > 5 && parse_u8(argv[5], &secret_delta) != 0) ||
        argc > 6 || target == 0u || max_queries < target ||
        secret_sbox >= 8u || secret_delta >= 16u) {
        fprintf(stderr,
                "Usage: %s [target] [max_queries] [seed] [secret_sbox] [secret_delta]\n",
                argv[0]);
        return 2;
    }

    if (scenery_init(&ctx, key) != 0) {
        fputs("FAIL: scenery_init failed.\n", stderr);
        return 1;
    }

    correct_output = scenery_sbox_correct(secret_delta);
    faulty_output = (uint8_t)((correct_output + 1u) & 0x0Fu);
    actual_word = scenery_round_key_sbox_word(
        ctx.round_keys[SCENERY_ROUNDS - 1u],
        secret_sbox
    );
    expected_missing = (uint8_t)(secret_delta ^ actual_word);

    scenery_fault_reset();
    if (scenery_fault_inject(
            secret_sbox,
            secret_delta,
            faulty_output) != 0) {
        fputs("FAIL: fault injection failed.\n", stderr);
        return 1;
    }

    public_file = fopen(
        "results/scenario2_unknown_detection_ciphertexts.csv",
        "w"
    );
    if (public_file == NULL) {
        perror("results/scenario2_unknown_detection_ciphertexts.csv");
        scenery_fault_reset();
        return 1;
    }
    fputs("ineffective_index,ciphertext\n", public_file);

    status = scenery_detection_collect(
        &ctx,
        target,
        max_queries,
        seed,
        &stats,
        write_public_sample,
        public_file
    );
    if (fclose(public_file) != 0) {
        perror("closing public dataset");
        scenery_fault_reset();
        return 1;
    }
    scenery_fault_reset();
    if (status != 0) {
        fprintf(stderr, "FAIL: dataset collector returned %d.\n", status);
        return 1;
    }

    theoretical_rate = scenery_detection_theoretical_ineffective_rate();
    empirical_rate =
        (double)stats.ineffective_count / (double)stats.total_queries;

    public_summary = fopen(
        "results/scenario2_unknown_detection_collection_summary.csv",
        "w"
    );
    if (public_summary == NULL) {
        perror("results/scenario2_unknown_detection_collection_summary.csv");
        return 1;
    }
    fputs("parameter,value\n", public_summary);
    fprintf(public_summary, "seed,0x%016" PRIX64 "\n", seed);
    fprintf(public_summary, "target_ineffective,%" PRIu64 "\n", target);
    fprintf(public_summary, "total_queries,%" PRIu64 "\n", stats.total_queries);
    fprintf(public_summary, "ineffective_count,%" PRIu64 "\n",
            stats.ineffective_count);
    fprintf(public_summary, "effective_count,%" PRIu64 "\n",
            stats.effective_count);
    fprintf(public_summary, "theoretical_rate,%.12f\n", theoretical_rate);
    fprintf(public_summary, "empirical_rate,%.12f\n", empirical_rate);
    fclose(public_summary);

    ground_truth = fopen(
        "results/scenario2_unknown_detection_ground_truth.csv",
        "w"
    );
    if (ground_truth == NULL) {
        perror("results/scenario2_unknown_detection_ground_truth.csv");
        return 1;
    }
    fputs("parameter,value\n", ground_truth);
    fprintf(ground_truth, "secret_sbox,%u\n", secret_sbox);
    fprintf(ground_truth, "secret_delta,0x%X\n", secret_delta);
    fprintf(ground_truth, "correct_sbox_output,0x%X\n", correct_output);
    fprintf(ground_truth, "faulty_sbox_output,0x%X\n", faulty_output);
    fprintf(ground_truth, "actual_sk28,0x%08" PRIX32 "\n",
            ctx.round_keys[SCENERY_ROUNDS - 1u]);
    fprintf(ground_truth, "actual_sk28_word,0x%X\n", actual_word);
    fprintf(ground_truth, "expected_missing,0x%X\n", expected_missing);
    fclose(ground_truth);

    puts("Scenario 2 / Step 1A: collect an unlabeled ineffective dataset");
    printf("public ineffective samples: %" PRIu64 "\n", stats.ineffective_count);
    printf("total oracle queries:       %" PRIu64 "\n", stats.total_queries);
    printf("effective events blocked:   %" PRIu64 "\n", stats.effective_count);
    printf("theoretical rate:           %.9f\n", theoretical_rate);
    printf("empirical rate:             %.9f\n", empirical_rate);
    puts("public dataset:  results/scenario2_unknown_detection_ciphertexts.csv");
    puts("public summary:  results/scenario2_unknown_detection_collection_summary.csv");
    puts("simulation truth: results/scenario2_unknown_detection_ground_truth.csv");
    puts("PASS: the public dataset discloses neither fault location nor delta.");
    return 0;
}
