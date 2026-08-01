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
#include "known_infection_attack.h"
#include "persistent_fault.h"
#include "reference_validation.h"

#define DEFAULT_SAMPLES UINT64_C(100000)
#define DEFAULT_SEED UINT64_C(0xA54FF53A5F1D36F1)
#define DEFAULT_KNOWN_DELTA UINT8_C(0x5a)

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

static int write_histogram_csv(
    const char *path,
    const lilliput_known_infection_result *result,
    uint8_t known_delta,
    const uint8_t actual_rtk[ROUND_TWEAKEY_BYTES]
)
{
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        return -1;
    }

    fputs("lane,value,count,is_observed_minimum,is_theoretical_target\n", file);
    for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
        const uint8_t theoretical_target =
            (uint8_t)(known_delta ^ actual_rtk[lane]);

        for (size_t value = 0; value < LILLIPUT_SBOX_DOMAIN; ++value) {
            fprintf(file,
                    "%zu,%zu,%" PRIu64 ",%u,%u\n",
                    lane,
                    value,
                    result->histogram[lane][value],
                    value == (size_t)result->minimum_value[lane] ? 1U : 0U,
                    value == (size_t)theoretical_target ? 1U : 0U);
        }
    }

    if (fclose(file) != 0) {
        perror(path);
        return -1;
    }

    return 0;
}

static int write_lane_summary_csv(
    const char *path,
    const lilliput_known_infection_result *result,
    uint8_t known_delta,
    const uint8_t actual_rtk[ROUND_TWEAKEY_BYTES]
)
{
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        return -1;
    }

    fputs("lane,minimum_value,minimum_count,second_minimum_count,gap,"
          "expected_minimum,recovered_rtk,actual_rtk,status\n",
          file);

    for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
        const uint8_t expected_minimum =
            (uint8_t)(known_delta ^ actual_rtk[lane]);
        const uint64_t gap =
            result->second_minimum_count[lane] - result->minimum_count[lane];
        const int lane_ok =
            (result->minimum_multiplicity[lane] == 1U) &&
            (result->minimum_value[lane] == expected_minimum) &&
            (result->recovered_round_tweakey[lane] == actual_rtk[lane]);

        fprintf(file,
                "%zu,%u,%" PRIu64 ",%" PRIu64 ",%" PRIu64
                ",%u,%u,%u,%s\n",
                lane,
                (unsigned int)result->minimum_value[lane],
                result->minimum_count[lane],
                result->second_minimum_count[lane],
                gap,
                (unsigned int)expected_minimum,
                (unsigned int)result->recovered_round_tweakey[lane],
                (unsigned int)actual_rtk[lane],
                lane_ok ? "PASS" : "FAIL");
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
            "Usage: %s [published_samples] [known_fault_input] [seed] "
            "[samples.csv] [histogram.csv] [lane_summary.csv]\n",
            program);
}

int main(int argc, char **argv)
{
    uint64_t sample_count = DEFAULT_SAMPLES;
    uint64_t seed = DEFAULT_SEED;
    uint8_t known_delta = DEFAULT_KNOWN_DELTA;
    const char *samples_path =
        "results/scenario3_published_ciphertexts.csv";
    const char *histogram_path =
        "results/scenario3_final_histogram.csv";
    const char *summary_path =
        "results/scenario3_lane_minima.csv";
    uint8_t key[KEY_BYTES];
    uint8_t tweak[TWEAK_BYTES];
    uint8_t actual_rtk[ROUND_TWEAKEY_BYTES];
    uint8_t *published_ciphertexts = NULL;
    lilliput_infection_stats stats;
    lilliput_known_infection_result result;
    struct dataset_context context;
    int status;
    int all_lanes_verified = 1;

    if ((argc > 1) && (parse_u64(argv[1], &sample_count) != 0)) {
        usage(argv[0]);
        return 2;
    }
    if ((argc > 2) && (parse_u8(argv[2], &known_delta) != 0)) {
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
        summary_path = argv[6];
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
        known_delta,
        (uint8_t)(lilliput_sbox_correct(known_delta) ^ UINT8_C(0x01))
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
     * Attack boundary: all public outputs are passed without internal event
     * labels.  The key, tweak, faulty S-box output, and true RTK are not
     * arguments.  Only the known persistent-fault input is supplied.
     */
    status = lilliput_known_infection_recover(
        published_ciphertexts,
        (size_t)sample_count,
        known_delta,
        &result
    );
    if (status != 0) {
        fprintf(stderr,
                "FAIL: known-infection recovery returned %d\n",
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

    if (write_histogram_csv(
            histogram_path, &result, known_delta, actual_rtk) != 0) {
        lilliput_fault_reset();
        free(published_ciphertexts);
        return 1;
    }
    if (write_lane_summary_csv(
            summary_path, &result, known_delta, actual_rtk) != 0) {
        lilliput_fault_reset();
        free(published_ciphertexts);
        return 1;
    }

    puts("Scenario 3: known-fault, infection-based SIPFA");
    puts("lane  minimum  min_count  second_min  gap  recovered_rtk  actual_rtk  status");

    for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
        const uint8_t expected_minimum =
            (uint8_t)(known_delta ^ actual_rtk[lane]);
        const uint64_t gap =
            result.second_minimum_count[lane] - result.minimum_count[lane];
        const int lane_ok =
            (result.minimum_multiplicity[lane] == 1U) &&
            (result.minimum_value[lane] == expected_minimum) &&
            (result.recovered_round_tweakey[lane] == actual_rtk[lane]);

        all_lanes_verified &= lane_ok;

        printf("%4zu  0x%02x     %9" PRIu64 "  %10" PRIu64
               "  %3" PRIu64 "  0x%02x           0x%02x        %s\n",
               lane,
               result.minimum_value[lane],
               result.minimum_count[lane],
               result.second_minimum_count[lane],
               gap,
               result.recovered_round_tweakey[lane],
               actual_rtk[lane],
               lane_ok ? "PASS" : "FAIL");
    }

    printf("\nknown fault input:      0x%02x\n", known_delta);
    printf("published samples:      %" PRIu64 "\n", stats.published_count);
    printf("internal ineffective:   %" PRIu64 "\n",
           stats.internal_ineffective_count);
    printf("internal effective:     %" PRIu64 "\n",
           stats.internal_effective_count);
    printf("ineffective rate:        %.6f\n",
           (double)stats.internal_ineffective_count /
           (double)stats.published_count);
    printf("samples CSV:            %s\n", samples_path);
    printf("histogram CSV:          %s\n", histogram_path);
    printf("lane summary CSV:       %s\n", summary_path);

    printf("recovered RTK[31]:      ");
    print_hex(stdout, result.recovered_round_tweakey, ROUND_TWEAKEY_BYTES);
    fputc('\n', stdout);
    printf("actual RTK[31]:         ");
    print_hex(stdout, actual_rtk, ROUND_TWEAKEY_BYTES);
    fputc('\n', stdout);

    lilliput_fault_reset();
    free(published_ciphertexts);

    if (!all_lanes_verified) {
        fputs("FAIL: at least one lane did not recover the theoretical minimum\n",
              stderr);
        return 1;
    }

    puts("PASS: Scenario 3 recovered the complete RTK[31] under a known "
         "persistent fault and infection-based countermeasure.");
    return 0;
}
