#include "known_detection_attack.h"
#include "scenery.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_DATASET   "results/scenario1_detection_ineffective.csv"
#define DEFAULT_HISTOGRAM "results/scenario1_target_sbox_histogram.csv"
#define DEFAULT_SUMMARY   "results/scenario1_word_recovery_summary.csv"

static int parse_u8(const char *text, uint8_t *value)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0' || parsed > UINT8_MAX) {
        return -1;
    }
    *value = (uint8_t)parsed;
    return 0;
}

static int hex_nibble(char character)
{
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    if (character >= 'A' && character <= 'F') {
        return character - 'A' + 10;
    }
    return -1;
}

static int parse_hex_block(
    const char *text,
    uint8_t output[SCENERY_BLOCK_SIZE]
)
{
    size_t index;

    if (text == NULL || strlen(text) != 2u * SCENERY_BLOCK_SIZE) {
        return -1;
    }

    for (index = 0u; index < SCENERY_BLOCK_SIZE; ++index) {
        const int high = hex_nibble(text[2u * index]);
        const int low = hex_nibble(text[2u * index + 1u]);
        if (high < 0 || low < 0) {
            return -1;
        }
        output[index] = (uint8_t)((unsigned int)(high << 4) |
                                  (unsigned int)low);
    }
    return 0;
}

static int load_released_dataset(
    const char *path,
    scenery_known_detection_result *result
)
{
    FILE *file = fopen(path, "r");
    char line[512];
    uint64_t line_number = 0u;

    if (file == NULL) {
        perror(path);
        return -1;
    }

    if (fgets(line, sizeof(line), file) == NULL) {
        fclose(file);
        fputs("FAIL: dataset is empty.\n", stderr);
        return -1;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        char *last_comma;
        char *ciphertext_text;
        size_t length;
        uint8_t ciphertext[SCENERY_BLOCK_SIZE];

        ++line_number;
        last_comma = strrchr(line, ',');
        if (last_comma == NULL) {
            fprintf(stderr, "FAIL: malformed CSV line %" PRIu64 ".\n",
                    line_number + 1u);
            fclose(file);
            return -1;
        }

        ciphertext_text = last_comma + 1;
        length = strlen(ciphertext_text);
        while (length > 0u &&
               (ciphertext_text[length - 1u] == '\n' ||
                ciphertext_text[length - 1u] == '\r')) {
            ciphertext_text[--length] = '\0';
        }

        if (parse_hex_block(ciphertext_text, ciphertext) != 0 ||
            scenery_known_detection_add_ciphertext(result, ciphertext) != 0) {
            fprintf(stderr, "FAIL: invalid ciphertext on CSV line %" PRIu64 ".\n",
                    line_number + 1u);
            fclose(file);
            return -1;
        }
    }

    if (ferror(file)) {
        perror(path);
        fclose(file);
        return -1;
    }
    if (fclose(file) != 0) {
        perror(path);
        return -1;
    }
    return result->sample_count > 0u ? 0 : -1;
}

static int write_histogram(
    const char *path,
    const scenery_known_detection_result *result
)
{
    FILE *file = fopen(path, "w");
    size_t value;

    if (file == NULL) {
        perror(path);
        return -1;
    }

    fputs("target_sbox,value,count,is_missing\n", file);
    for (value = 0u; value < SCENERY_ATTACK_DOMAIN; ++value) {
        fprintf(file, "%u,%zu,%" PRIu64 ",%u\n",
                result->target_sbox,
                value,
                result->histogram[value],
                result->histogram[value] == 0u ? 1u : 0u);
    }
    if (fclose(file) != 0) {
        perror(path);
        return -1;
    }
    return 0;
}

static int write_summary(
    const char *path,
    const scenery_known_detection_result *result,
    uint32_t actual_round_key,
    uint8_t actual_word,
    int verified
)
{
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        return -1;
    }

    fputs("parameter,value\n", file);
    fprintf(file, "target_sbox,%u\n", result->target_sbox);
    fprintf(file, "known_delta,0x%X\n", result->known_delta);
    fprintf(file, "sample_count,%" PRIu64 "\n", result->sample_count);
    fprintf(file, "missing_count,%zu\n", result->missing_count);
    if (result->missing_count == 1u) {
        fprintf(file, "missing_value,0x%X\n", result->missing_values[0]);
    }
    fprintf(file, "recovered_sk28_word,0x%X\n",
            result->recovered_round_key_word);
    fprintf(file, "actual_sk28,0x%08" PRIX32 "\n", actual_round_key);
    fprintf(file, "actual_sk28_word,0x%X\n", actual_word);
    fprintf(file, "verified,%s\n", verified ? "PASS" : "FAIL");

    if (fclose(file) != 0) {
        perror(path);
        return -1;
    }
    return 0;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s [dataset.csv] [target_sbox] [known_delta] "
            "[histogram.csv] [summary.csv]\n",
            program);
}

int main(int argc, char **argv)
{
    const uint8_t key[SCENERY_KEY_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99
    };
    const char *dataset_path = DEFAULT_DATASET;
    const char *histogram_path = DEFAULT_HISTOGRAM;
    const char *summary_path = DEFAULT_SUMMARY;
    uint8_t target_sbox = 3u;
    uint8_t known_delta = 0x5u;
    scenery_known_detection_result result;
    scenery_ctx verification_ctx;
    uint32_t actual_round_key;
    uint8_t actual_word;
    int recovery_status;
    int verified;
    size_t value;

    if (argc > 1) {
        dataset_path = argv[1];
    }
    if (argc > 2 && parse_u8(argv[2], &target_sbox) != 0) {
        usage(argv[0]);
        return 2;
    }
    if (argc > 3 && parse_u8(argv[3], &known_delta) != 0) {
        usage(argv[0]);
        return 2;
    }
    if (argc > 4) {
        histogram_path = argv[4];
    }
    if (argc > 5) {
        summary_path = argv[5];
    }
    if (argc > 6 || target_sbox >= SCENERY_ATTACK_SBOXES ||
        known_delta >= SCENERY_ATTACK_DOMAIN) {
        usage(argv[0]);
        return 2;
    }

    scenery_known_detection_result_init(
        &result,
        target_sbox,
        known_delta
    );
    if (load_released_dataset(dataset_path, &result) != 0) {
        return 1;
    }

    recovery_status = scenery_known_detection_recover_word(&result);

    /* Ground truth is computed only after recovery, solely for verification. */
    if (scenery_init(&verification_ctx, key) != 0) {
        fputs("FAIL: could not initialize verification context.\n", stderr);
        return 1;
    }
    actual_round_key = verification_ctx.round_keys[SCENERY_ROUNDS - 1u];
    actual_word = scenery_round_key_sbox_word(actual_round_key, target_sbox);
    verified = recovery_status == 0 && result.success &&
        result.recovered_round_key_word == actual_word;

    puts("Scenario 1 / Step 3: Algorithm-1 target-word recovery");
    printf("dataset:               %s\n", dataset_path);
    printf("target logical S-box:  %u\n", target_sbox);
    printf("known delta:           0x%X\n", known_delta);
    printf("released samples:      %" PRIu64 "\n", result.sample_count);
    puts("value  count");
    for (value = 0u; value < SCENERY_ATTACK_DOMAIN; ++value) {
        printf("0x%zX   %" PRIu64 "%s\n",
               value,
               result.histogram[value],
               result.histogram[value] == 0u ? "  <-- missing" : "");
    }
    printf("missing count:         %zu\n", result.missing_count);
    if (result.missing_count == 1u) {
        printf("missing value:         0x%X\n", result.missing_values[0]);
    }
    printf("recovered SK28 word:   0x%X\n", result.recovered_round_key_word);
    printf("actual SK28:           %08" PRIX32 "\n", actual_round_key);
    printf("actual SK28 word:      0x%X\n", actual_word);
    printf("histogram CSV:         %s\n", histogram_path);
    printf("summary CSV:           %s\n", summary_path);

    if (write_histogram(histogram_path, &result) != 0 ||
        write_summary(summary_path, &result, actual_round_key,
                      actual_word, verified) != 0) {
        return 1;
    }

    if (!verified) {
        fputs("FAIL: target-word recovery was not uniquely verified.\n", stderr);
        return 1;
    }

    puts("PASS: the unique missing value recovered the target four bits of SK28.");
    return 0;
}
