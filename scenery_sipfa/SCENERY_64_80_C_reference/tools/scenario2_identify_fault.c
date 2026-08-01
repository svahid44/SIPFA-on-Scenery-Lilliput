#include "unknown_detection_attack.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_INPUT \
    "results/scenario2_unknown_detection_ciphertexts.csv"

static int hex_nibble(char character, uint8_t *value)
{
    if (character >= '0' && character <= '9') {
        *value = (uint8_t)(character - '0');
        return 0;
    }
    character = (char)toupper((unsigned char)character);
    if (character >= 'A' && character <= 'F') {
        *value = (uint8_t)(character - 'A' + 10);
        return 0;
    }
    return -1;
}

static int parse_ciphertext_hex(
    const char *text,
    uint8_t ciphertext[SCENERY_BLOCK_SIZE]
)
{
    size_t byte;

    if (text == NULL || strlen(text) < 2u * SCENERY_BLOCK_SIZE) {
        return -1;
    }
    for (byte = 0u; byte < SCENERY_BLOCK_SIZE; ++byte) {
        uint8_t high;
        uint8_t low;
        if (hex_nibble(text[2u * byte], &high) != 0 ||
            hex_nibble(text[2u * byte + 1u], &low) != 0) {
            return -1;
        }
        ciphertext[byte] = (uint8_t)((high << 4) | low);
    }
    return 0;
}

int main(int argc, char **argv)
{
    const char *input_path = DEFAULT_INPUT;
    FILE *input;
    FILE *histogram_file;
    FILE *summary_file;
    scenery_unknown_detection_result attack;
    char line[256];
    size_t line_number = 0u;
    size_t sbox;
    int status;

    if (argc > 1) {
        input_path = argv[1];
    }
    if (argc > 2) {
        fprintf(stderr, "Usage: %s [public_ciphertext_csv]\n", argv[0]);
        return 2;
    }

    input = fopen(input_path, "r");
    if (input == NULL) {
        perror(input_path);
        return 1;
    }

    scenery_unknown_detection_result_init(&attack);
    while (fgets(line, sizeof(line), input) != NULL) {
        char *comma;
        char *newline;
        uint8_t ciphertext[SCENERY_BLOCK_SIZE];

        ++line_number;
        if (line_number == 1u) {
            continue;
        }
        comma = strchr(line, ',');
        if (comma == NULL) {
            fprintf(stderr, "FAIL: malformed CSV line %zu.\n", line_number);
            fclose(input);
            return 1;
        }
        ++comma;
        newline = strpbrk(comma, "\r\n");
        if (newline != NULL) {
            *newline = '\0';
        }
        if (parse_ciphertext_hex(comma, ciphertext) != 0 ||
            scenery_unknown_detection_add_ciphertext(
                &attack,
                ciphertext) != 0) {
            fprintf(stderr, "FAIL: invalid ciphertext on line %zu.\n",
                    line_number);
            fclose(input);
            return 1;
        }
    }
    if (fclose(input) != 0) {
        perror("closing public dataset");
        return 1;
    }

    status = scenery_unknown_detection_identify_fault(&attack);

    histogram_file = fopen(
        "results/scenario2_unknown_detection_histograms.csv",
        "w"
    );
    if (histogram_file == NULL) {
        perror("results/scenario2_unknown_detection_histograms.csv");
        return 1;
    }
    fputs("sbox,value,count,is_missing,is_detected_pair\n", histogram_file);
    for (sbox = 0u; sbox < SCENERY_UNKNOWN_DETECTION_SBOXES; ++sbox) {
        size_t value;
        for (value = 0u; value < SCENERY_UNKNOWN_DETECTION_DOMAIN; ++value) {
            const unsigned int missing =
                attack.histogram[sbox][value] == 0u ? 1u : 0u;
            const unsigned int detected =
                attack.success && attack.detected_sbox == sbox &&
                attack.detected_missing_value == value ? 1u : 0u;
            fprintf(histogram_file,
                    "%zu,0x%zX,%" PRIu64 ",%u,%u\n",
                    sbox,
                    value,
                    attack.histogram[sbox][value],
                    missing,
                    detected);
        }
    }
    fclose(histogram_file);

    summary_file = fopen(
        "results/scenario2_fault_identification_summary.csv",
        "w"
    );
    if (summary_file == NULL) {
        perror("results/scenario2_fault_identification_summary.csv");
        return 1;
    }
    fputs("parameter,value\n", summary_file);
    fprintf(summary_file, "sample_count,%" PRIu64 "\n", attack.sample_count);
    fprintf(summary_file, "global_missing_count,%zu\n",
            attack.total_missing_count);
    if (attack.success) {
        fprintf(summary_file, "detected_sbox,%u\n", attack.detected_sbox);
        fprintf(summary_file, "detected_missing_value,0x%X\n",
                attack.detected_missing_value);
    } else {
        fputs("detected_sbox,AMBIGUOUS\n", summary_file);
        fputs("detected_missing_value,AMBIGUOUS\n", summary_file);
    }
    fprintf(summary_file, "status,%s\n", attack.success ? "PASS" : "AMBIGUOUS");
    fclose(summary_file);

    puts("Scenario 2 / Step 1B: identify the unknown faulty S-box");
    printf("public dataset:       %s\n", input_path);
    printf("ineffective samples:  %" PRIu64 "\n", attack.sample_count);
    puts("sbox  missing_count  missing_values");
    for (sbox = 0u; sbox < SCENERY_UNKNOWN_DETECTION_SBOXES; ++sbox) {
        size_t index;
        printf("%4zu  %13zu  ", sbox, attack.missing_count_per_sbox[sbox]);
        for (index = 0u; index < attack.missing_count_per_sbox[sbox]; ++index) {
            printf("0x%X ", attack.missing_values[sbox][index]);
        }
        putchar('\n');
    }
    printf("global missing count: %zu\n", attack.total_missing_count);
    if (attack.success) {
        printf("detected S-box:       %u\n", attack.detected_sbox);
        printf("public missing value: 0x%X\n", attack.detected_missing_value);
        puts("relation: missing = secret_delta XOR SK28[detected_sbox]");
    }
    puts("histograms: results/scenario2_unknown_detection_histograms.csv");
    puts("summary:    results/scenario2_fault_identification_summary.csv");

    if (status != 0 || !attack.success) {
        fputs("FAIL: more samples are required to obtain one global missing value.\n",
              stderr);
        return 1;
    }

    puts("PASS: Algorithm 2 identified the unknown fault location without knowing delta or the key.");
    return 0;
}
