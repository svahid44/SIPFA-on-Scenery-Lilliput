#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "constants.h"
#include "detection_dataset.h"
#include "infection_dataset.h"
#include "persistent_fault.h"
#include "reference_validation.h"
#include "unknown_infection_attack.h"

#define DEFAULT_SAMPLES UINT64_C(100000)
#define DEFAULT_SECRET_DELTA UINT8_C(0x5a)
#define DEFAULT_SEED UINT64_C(0x9B05688C2B3E6C1F)

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

static int capture_published(
    uint64_t sample_index,
    const uint8_t ciphertext[BLOCK_BYTES],
    void *user_data
)
{
    struct dataset_context *context = user_data;
    size_t index;

    if ((context == NULL) || (context->file == NULL) ||
        (sample_index == 0U) ||
        (sample_index > (uint64_t)context->capacity)) {
        return -1;
    }

    index = (size_t)(sample_index - 1U);
    memcpy(context->ciphertexts + index * BLOCK_BYTES,
           ciphertext,
           BLOCK_BYTES);

    fprintf(context->file, "%" PRIu64 ",", sample_index);
    print_hex(context->file, ciphertext, BLOCK_BYTES);
    fputc('\n', context->file);

    return ferror(context->file) ? -1 : 0;
}

static int write_final_histogram_csv(
    const char *path,
    const lilliput_unknown_infection_result *result,
    size_t sample_count
)
{
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        return -1;
    }

    fputs("lane,value,count,probability,is_minimum,lane_sei\n", file);
    for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
        for (size_t value = 0; value < LILLIPUT_SBOX_DOMAIN; ++value) {
            fprintf(file,
                    "%zu,%zu,%" PRIu64 ",%.12e,%u,%.12e\n",
                    lane,
                    value,
                    result->final_histogram[lane][value],
                    (double)result->final_histogram[lane][value] /
                        (double)sample_count,
                    result->final_minimum[lane] == (uint8_t)value ? 1U : 0U,
                    result->final_lane_sei[lane]);
        }
    }

    if (fclose(file) != 0) {
        perror(path);
        return -1;
    }

    return 0;
}

static int write_candidates_csv(
    const char *path,
    const lilliput_unknown_infection_result *result
)
{
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        return -1;
    }

    fputs("delta_candidate,aggregate_sei,rank,is_recovered", file);
    for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
        fprintf(file, ",lane%zu_sei", lane);
    }
    fputc('\n', file);

    for (size_t delta = 0;
         delta < LILLIPUT_UNKNOWN_INFECTION_CANDIDATES;
         ++delta) {
        fprintf(file,
                "%zu,%.12e,%zu,%u",
                delta,
                result->candidate_sei[delta],
                result->candidate_rank[delta],
                result->recovered_delta == (uint8_t)delta ? 1U : 0U);

        for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
            fprintf(file,
                    ",%.12e",
                    result->candidate_lane_sei[delta][lane]);
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
            "Usage: %s [published_samples] [secret_fault_input] [seed] "
            "[samples.csv] [histogram.csv] [candidates.csv]\n",
            program);
}

int main(int argc, char **argv)
{
    uint64_t sample_count = DEFAULT_SAMPLES;
    uint64_t seed = DEFAULT_SEED;
    uint8_t secret_delta = DEFAULT_SECRET_DELTA;
    const char *samples_path =
        "results/scenario4_published_ciphertexts.csv";
    const char *histogram_path =
        "results/scenario4_final_histogram.csv";
    const char *candidates_path =
        "results/scenario4_candidates.csv";
    uint8_t key[KEY_BYTES];
    uint8_t tweak[TWEAK_BYTES];
    uint8_t actual_rtk[ROUND_TWEAKEY_BYTES];
    uint8_t *published_ciphertexts = NULL;
    lilliput_infection_stats stats;
    lilliput_unknown_infection_result result;
    struct dataset_context context;
    int status;

    if ((argc > 1) && (parse_u64(argv[1], &sample_count) != 0)) {
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
        candidates_path = argv[6];
    }
    if (argc > 7) {
        usage(argv[0]);
        return 2;
    }

    if ((sample_count == 0U) ||
        (sample_count > (uint64_t)(SIZE_MAX / BLOCK_BYTES))) {
        fputs("invalid published_samples\n", stderr);
        return 2;
    }

    for (size_t i = 0; i < KEY_BYTES; ++i) {
        key[i] = (uint8_t)i;
    }
    for (size_t i = 0; i < TWEAK_BYTES; ++i) {
        tweak[i] = (uint8_t)i;
    }

    published_ciphertexts = malloc((size_t)sample_count * BLOCK_BYTES);
    if (published_ciphertexts == NULL) {
        fputs("could not allocate public infection dataset\n", stderr);
        return 1;
    }

    context.file = fopen(samples_path, "w");
    if (context.file == NULL) {
        perror(samples_path);
        free(published_ciphertexts);
        return 1;
    }
    context.ciphertexts = published_ciphertexts;
    context.capacity = (size_t)sample_count;
    fputs("sample_index,ciphertext\n", context.file);

    lilliput_fault_reset();
    status = lilliput_fault_inject(
        secret_delta,
        (uint8_t)(lilliput_sbox_correct(secret_delta) ^ UINT8_C(0x01))
    );
    if (status != 0) {
        fclose(context.file);
        free(published_ciphertexts);
        fputs("persistent fault injection failed\n", stderr);
        return 1;
    }

    status = lilliput_infection_collect(
        key,
        tweak,
        sample_count,
        seed,
        &stats,
        capture_published,
        &context
    );
    if (fclose(context.file) != 0) {
        perror(samples_path);
        free(published_ciphertexts);
        return 1;
    }
    if (status != 0) {
        fprintf(stderr,
                "infection dataset collection failed with status %d\n",
                status);
        free(published_ciphertexts);
        return 1;
    }

    /*
     * Attack boundary: only unlabeled public ciphertexts are passed below.
     * The secret delta, key, tweak, event labels, and true RTK are not
     * arguments to the recovery function.
     */
    status = lilliput_unknown_infection_recover(
        published_ciphertexts,
        (size_t)sample_count,
        &result
    );
    if (status != 0) {
        fprintf(stderr,
                "FAIL: unknown-infection recovery returned %d\n",
                status);
        lilliput_fault_reset();
        free(published_ciphertexts);
        return 1;
    }

    if (lilliput_reference_round_tweakey(
            key, tweak, ROUNDS - 1U, actual_rtk) != 0) {
        lilliput_fault_reset();
        free(published_ciphertexts);
        fputs("could not compute reference final-round tweakey\n", stderr);
        return 1;
    }

    if (write_final_histogram_csv(
            histogram_path, &result, (size_t)sample_count) != 0) {
        lilliput_fault_reset();
        free(published_ciphertexts);
        return 1;
    }
    if (write_candidates_csv(candidates_path, &result) != 0) {
        lilliput_fault_reset();
        free(published_ciphertexts);
        return 1;
    }

    puts("Scenario 4: unknown-fault, infection-based SIPFA");
    puts("lane  final_minimum  final_SEI       relative_RTK_to_lane0");
    for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
        printf("%4zu  0x%02x           %.6e  0x%02x\n",
               lane,
               result.final_minimum[lane],
               result.final_lane_sei[lane],
               result.relative_round_tweakey[lane]);
    }

    puts("\nTop SEI-ranked delta candidates:");
    puts("rank  delta  aggregate_SEI");
    for (size_t rank = 1U; rank <= 10U; ++rank) {
        for (size_t delta = 0;
             delta < LILLIPUT_UNKNOWN_INFECTION_CANDIDATES;
             ++delta) {
            if (result.candidate_rank[delta] == rank) {
                printf("%4zu  0x%02zx  %.12e\n",
                       rank,
                       delta,
                       result.candidate_sei[delta]);
            }
        }
    }

    printf("\npublished samples:      %" PRIu64 "\n", stats.published_count);
    printf("internal ineffective:   %" PRIu64 "\n",
           stats.internal_ineffective_count);
    printf("internal effective:     %" PRIu64 "\n",
           stats.internal_effective_count);
    printf("ineffective rate:        %.6f\n",
           (double)stats.internal_ineffective_count /
           (double)stats.published_count);
    printf("best aggregate SEI:     %.12e\n", result.best_score);
    printf("second aggregate SEI:   %.12e\n", result.second_best_score);
    printf("SEI gap:                %.12e\n",
           result.best_score - result.second_best_score);
    printf("samples CSV:            %s\n", samples_path);
    printf("histogram CSV:          %s\n", histogram_path);
    printf("candidates CSV:         %s\n", candidates_path);
    printf("recovered fault input:  0x%02x\n", result.recovered_delta);
    printf("actual fault input:     0x%02x\n", secret_delta);
    printf("recovered RTK[31]:      ");
    print_hex(stdout, result.recovered_round_tweakey, ROUND_TWEAKEY_BYTES);
    fputc('\n', stdout);
    printf("actual RTK[31]:         ");
    print_hex(stdout, actual_rtk, ROUND_TWEAKEY_BYTES);
    fputc('\n', stdout);

    lilliput_fault_reset();
    free(published_ciphertexts);

    if ((result.recovered_delta != secret_delta) ||
        (memcmp(result.recovered_round_tweakey,
                actual_rtk,
                ROUND_TWEAKEY_BYTES) != 0)) {
        fputs("FAIL: recovered values do not match simulation ground truth\n",
              stderr);
        return 1;
    }

    puts("PASS: Scenario 4 recovered the unknown persistent fault input and "
         "complete RTK[31] under an infection-based countermeasure.");
    return 0;
}
