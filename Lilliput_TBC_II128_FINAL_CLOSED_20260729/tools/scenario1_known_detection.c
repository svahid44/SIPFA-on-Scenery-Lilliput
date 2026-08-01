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

#define DEFAULT_TARGET UINT64_C(4000)
#define DEFAULT_MAX_QUERIES UINT64_C(100000)
#define DEFAULT_SEED UINT64_C(0x243F6A8885A308D3)

struct csv_context {
    FILE *file;
};

static void print_hex(FILE *stream, const uint8_t *data, size_t length)
{
    for (size_t i = 0; i < length; ++i) {
        fprintf(stream, "%02x", data[i]);
    }
}

static int write_sample(
    uint64_t query_index,
    uint64_t ineffective_index,
    const uint8_t ciphertext[BLOCK_BYTES],
    void *user_data
)
{
    struct csv_context *context = user_data;

    if ((context == NULL) || (context->file == NULL)) {
        return -1;
    }

    fprintf(context->file, "%" PRIu64 ",%" PRIu64 ",", query_index, ineffective_index);
    print_hex(context->file, ciphertext, BLOCK_BYTES);
    fputc('\n', context->file);

    return ferror(context->file) ? -1 : 0;
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

static int write_histogram_csv(
    const char *path,
    const lilliput_detection_stats *stats,
    uint8_t delta,
    const uint8_t final_round_tweakey[ROUND_TWEAKEY_BYTES]
)
{
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        return -1;
    }

    fputs("lane,value,count,is_missing,expected_missing\n", file);
    for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
        const uint8_t expected_missing = (uint8_t)(delta ^ final_round_tweakey[lane]);
        for (size_t value = 0; value < LILLIPUT_SBOX_DOMAIN; ++value) {
            fprintf(file,
                    "%zu,%zu,%" PRIu64 ",%u,%u\n",
                    lane,
                    value,
                    stats->histogram[lane][value],
                    stats->histogram[lane][value] == 0U ? 1U : 0U,
                    (unsigned int)expected_missing);
        }
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
            "Usage: %s [target_ineffective] [fault_input] [seed] [samples.csv] [histogram.csv]\n",
            program);
}

int main(int argc, char **argv)
{
    uint64_t target = DEFAULT_TARGET;
    uint64_t seed = DEFAULT_SEED;
    uint8_t delta = UINT8_C(0x00);
    const char *samples_path = "results/scenario1_ineffective_samples.csv";
    const char *histogram_path = "results/scenario1_histogram.csv";
    uint8_t key[KEY_BYTES];
    uint8_t tweak[TWEAK_BYTES];
    uint8_t final_round_tweakey[ROUND_TWEAKEY_BYTES];
    uint8_t recovered_round_tweakey[ROUND_TWEAKEY_BYTES];
    lilliput_detection_stats stats;
    struct csv_context csv;
    int all_lanes_verified = 1;

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
        histogram_path = argv[5];
    }
    if (argc > 6) {
        usage(argv[0]);
        return 2;
    }
    if (target == 0U) {
        fputs("target_ineffective must be nonzero\n", stderr);
        return 2;
    }

    for (size_t i = 0; i < KEY_BYTES; ++i) {
        key[i] = (uint8_t)i;
    }
    for (size_t i = 0; i < TWEAK_BYTES; ++i) {
        tweak[i] = (uint8_t)i;
    }

    lilliput_fault_reset();
    {
        const uint8_t faulty_output =
            (uint8_t)(lilliput_sbox_correct(delta) ^ UINT8_C(0x01));
        if (lilliput_fault_inject(delta, faulty_output) != 0) {
            fputs("persistent fault injection failed\n", stderr);
            return 1;
        }
    }

    csv.file = fopen(samples_path, "w");
    if (csv.file == NULL) {
        perror(samples_path);
        return 1;
    }
    fputs("query_index,ineffective_index,ciphertext\n", csv.file);

    {
        uint64_t max_queries = DEFAULT_MAX_QUERIES;
        if (target > DEFAULT_MAX_QUERIES / 4U) {
            if (target > UINT64_MAX / 4U) {
                fclose(csv.file);
                fputs("target is too large\n", stderr);
                return 2;
            }
            max_queries = target * 4U;
        }

        const int status = lilliput_detection_collect(key,
                                                       tweak,
                                                       target,
                                                       max_queries,
                                                       seed,
                                                       &stats,
                                                       write_sample,
                                                       &csv);
        if (fclose(csv.file) != 0) {
            perror(samples_path);
            return 1;
        }
        if (status != 0) {
            fprintf(stderr, "dataset collection failed with status %d\n", status);
            return 1;
        }
    }

    if (lilliput_reference_round_tweakey(key,
                                       tweak,
                                       ROUNDS - 1U,
                                       final_round_tweakey) != 0) {
        fputs("could not compute final-round tweakey\n", stderr);
        return 1;
    }

    puts("lane  missing  expected  recovered_rtk  actual_rtk  status");
    for (size_t lane = 0; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
        uint8_t missing[LILLIPUT_SBOX_DOMAIN];
        const size_t missing_count =
            lilliput_histogram_missing_values(stats.histogram[lane], missing);
        const uint8_t expected_missing = (uint8_t)(delta ^ final_round_tweakey[lane]);

        if (missing_count == 1U) {
            recovered_round_tweakey[lane] = (uint8_t)(missing[0] ^ delta);
        } else {
            recovered_round_tweakey[lane] = 0U;
        }

        const int lane_ok =
            (missing_count == 1U) &&
            (missing[0] == expected_missing) &&
            (recovered_round_tweakey[lane] == final_round_tweakey[lane]);
        all_lanes_verified &= lane_ok;

        printf("%4zu  ", lane);
        if (missing_count == 1U) {
            printf("0x%02x   ", missing[0]);
        } else {
            printf("(%3zu)  ", missing_count);
        }
        printf("0x%02x     0x%02x          0x%02x        %s\n",
               expected_missing,
               recovered_round_tweakey[lane],
               final_round_tweakey[lane],
               lane_ok ? "PASS" : "FAIL");
    }

    if (write_histogram_csv(histogram_path, &stats, delta, final_round_tweakey) != 0) {
        return 1;
    }

    printf("\nqueries:             %" PRIu64 "\n", stats.total_queries);
    printf("ineffective samples: %" PRIu64 "\n", stats.ineffective_count);
    printf("effective samples:   %" PRIu64 "\n", stats.effective_count);
    printf("ineffective rate:     %.6f\n",
           (double)stats.ineffective_count / (double)stats.total_queries);
    printf("fault input delta:    0x%02x\n", delta);
    printf("samples CSV:          %s\n", samples_path);
    printf("histogram CSV:        %s\n", histogram_path);

    printf("recovered RTK[31]:    ");
    print_hex(stdout, recovered_round_tweakey, ROUND_TWEAKEY_BYTES);
    fputc('\n', stdout);
    printf("actual RTK[31]:       ");
    print_hex(stdout, final_round_tweakey, ROUND_TWEAKEY_BYTES);
    fputc('\n', stdout);

    lilliput_fault_reset();
    if (!all_lanes_verified) {
        fputs("FAIL: at least one lane did not yield the unique theoretical missing value\n", stderr);
        return 1;
    }

    puts("PASS: Scenario 1 recovered the complete final-round tweakey.");
    return 0;
}
