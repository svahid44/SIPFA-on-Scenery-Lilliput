#include "known_detection_attack.h"
#include "known_infection_attack.h"
#include "scenery.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int hex_value(int character)
{
    if (character >= '0' && character <= '9') {
        return character - '0';
    }
    character = tolower((unsigned char)character);
    if (character >= 'a' && character <= 'f') {
        return character - 'a' + 10;
    }
    return -1;
}

static int parse_block_hex(
    const char *text,
    uint8_t block[SCENERY_BLOCK_SIZE]
)
{
    size_t byte;

    if (text == NULL || strlen(text) != SCENERY_BLOCK_SIZE * 2u) {
        return -1;
    }
    for (byte = 0u; byte < SCENERY_BLOCK_SIZE; ++byte) {
        const int high = hex_value((unsigned char)text[2u * byte]);
        const int low = hex_value((unsigned char)text[2u * byte + 1u]);
        if (high < 0 || low < 0) {
            return -1;
        }
        block[byte] = (uint8_t)((unsigned int)(high << 4) | (unsigned int)low);
    }
    return 0;
}

int main(void)
{
    const uint8_t key[SCENERY_KEY_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99
    };
    const uint8_t target_sbox = 3u;
    const uint8_t delta = 0x5u;
    scenery_known_infection_result result;
    scenery_ctx verification_ctx;
    FILE *dataset_file;
    FILE *histogram_file;
    FILE *summary_file;
    char line[256];
    int status;
    uint8_t actual_word;
    uint8_t expected_minimum;
    size_t value;

    scenery_known_infection_result_init(&result, target_sbox, delta);

    dataset_file = fopen(
        "results/scenario3_known_infection_ciphertexts.csv",
        "r"
    );
    if (dataset_file == NULL) {
        perror("results/scenario3_known_infection_ciphertexts.csv");
        return 1;
    }

    if (fgets(line, sizeof(line), dataset_file) == NULL) {
        fputs("FAIL: public dataset is empty.\n", stderr);
        fclose(dataset_file);
        return 1;
    }

    while (fgets(line, sizeof(line), dataset_file) != NULL) {
        char *comma = strchr(line, ',');
        char *ciphertext_text;
        char *newline;
        uint8_t ciphertext[SCENERY_BLOCK_SIZE];

        if (comma == NULL) {
            fputs("FAIL: malformed public dataset row.\n", stderr);
            fclose(dataset_file);
            return 1;
        }
        ciphertext_text = comma + 1;
        newline = strpbrk(ciphertext_text, "\r\n");
        if (newline != NULL) {
            *newline = '\0';
        }
        if (parse_block_hex(ciphertext_text, ciphertext) != 0 ||
            scenery_known_infection_add_ciphertext(&result, ciphertext) != 0) {
            fputs("FAIL: invalid ciphertext in public dataset.\n", stderr);
            fclose(dataset_file);
            return 1;
        }
    }
    if (fclose(dataset_file) != 0) {
        perror("closing public dataset");
        return 1;
    }

    status = scenery_known_infection_recover_word(&result);
    if (status != 0 || !result.success) {
        fprintf(stderr,
                "FAIL: minimum-frequency recovery returned %d (multiplicity=%zu).\n",
                status,
                result.minimum_multiplicity);
        return 1;
    }

    /* Ground truth is introduced only after the public attack has completed. */
    if (scenery_init(&verification_ctx, key) != 0) {
        fputs("FAIL: verification context initialization failed.\n", stderr);
        return 1;
    }
    actual_word = scenery_round_key_sbox_word(
        verification_ctx.round_keys[SCENERY_ROUNDS - 1u],
        target_sbox
    );
    expected_minimum = (uint8_t)(delta ^ actual_word);

    histogram_file = fopen(
        "results/scenario3_known_infection_histogram.csv",
        "w"
    );
    if (histogram_file == NULL) {
        perror("results/scenario3_known_infection_histogram.csv");
        return 1;
    }
    fputs("value,count,is_observed_minimum,is_theoretical_target\n",
          histogram_file);
    for (value = 0u; value < SCENERY_ATTACK_DOMAIN; ++value) {
        fprintf(histogram_file,
                "0x%zX,%" PRIu64 ",%u,%u\n",
                value,
                result.histogram[value],
                value == (size_t)result.minimum_value ? 1u : 0u,
                value == (size_t)expected_minimum ? 1u : 0u);
    }
    if (fclose(histogram_file) != 0) {
        perror("closing histogram");
        return 1;
    }

    summary_file = fopen(
        "results/scenario3_known_infection_recovery_summary.csv",
        "w"
    );
    if (summary_file == NULL) {
        perror("results/scenario3_known_infection_recovery_summary.csv");
        return 1;
    }
    fputs("parameter,value\n", summary_file);
    fprintf(summary_file, "target_sbox,%u\n", target_sbox);
    fprintf(summary_file, "known_delta,0x%X\n", delta);
    fprintf(summary_file, "sample_count,%" PRIu64 "\n", result.sample_count);
    fprintf(summary_file, "minimum_value,0x%X\n", result.minimum_value);
    fprintf(summary_file, "minimum_count,%" PRIu64 "\n", result.minimum_count);
    fprintf(summary_file, "second_minimum_count,%" PRIu64 "\n",
            result.second_minimum_count);
    fprintf(summary_file, "minimum_gap,%" PRIu64 "\n",
            result.second_minimum_count - result.minimum_count);
    fprintf(summary_file, "minimum_multiplicity,%zu\n",
            result.minimum_multiplicity);
    fprintf(summary_file, "recovered_sk28_word,0x%X\n",
            result.recovered_round_key_word);
    fprintf(summary_file, "actual_sk28_word,0x%X\n", actual_word);
    fprintf(summary_file, "expected_minimum,0x%X\n", expected_minimum);
    fprintf(summary_file, "verified,%s\n",
            result.minimum_value == expected_minimum &&
            result.recovered_round_key_word == actual_word
                ? "PASS"
                : "FAIL");
    if (fclose(summary_file) != 0) {
        perror("closing recovery summary");
        return 1;
    }

    puts("Scenario 3 / Step 1B: Algorithm-3 minimum-frequency word recovery");
    printf("public dataset samples:   %" PRIu64 "\n", result.sample_count);
    printf("known target S-box:       %u\n", target_sbox);
    printf("known delta:              0x%X\n", delta);
    puts("value  count");
    for (value = 0u; value < SCENERY_ATTACK_DOMAIN; ++value) {
        printf("0x%zX   %" PRIu64 "%s\n",
               value,
               result.histogram[value],
               value == (size_t)result.minimum_value
                   ? "  <-- unique minimum"
                   : "");
    }
    printf("minimum value:            0x%X\n", result.minimum_value);
    printf("minimum count:            %" PRIu64 "\n", result.minimum_count);
    printf("second minimum count:     %" PRIu64 "\n",
           result.second_minimum_count);
    printf("minimum gap:              %" PRIu64 "\n",
           result.second_minimum_count - result.minimum_count);
    printf("recovered SK28 word:      0x%X\n",
           result.recovered_round_key_word);
    printf("actual SK28 word:         0x%X\n", actual_word);
    puts("histogram: results/scenario3_known_infection_histogram.csv");
    puts("summary:   results/scenario3_known_infection_recovery_summary.csv");

    if (result.minimum_value != expected_minimum ||
        result.recovered_round_key_word != actual_word) {
        fputs("FAIL: recovered minimum or key word differs from ground truth.\n",
              stderr);
        return 1;
    }

    puts("PASS: the least-frequent public value recovered the target four bits of SK28.");
    return 0;
}
