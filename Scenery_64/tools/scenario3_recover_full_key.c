#include "known_detection_attack.h"
#include "known_infection_attack.h"
#include "scenery.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

static int parse_block_hex(const char *text, uint8_t block[SCENERY_BLOCK_SIZE])
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
    const uint8_t delta = 0x5u;
    scenery_known_infection_full_result result;
    scenery_ctx verification_ctx;
    FILE *dataset_file;
    FILE *histograms_file;
    FILE *summary_file;
    char line[256];
    uint32_t actual_sk28;
    size_t sbox;
    int status;

    scenery_known_infection_full_result_init(&result, delta);

    dataset_file = fopen(
        "results/scenario3_all_sboxes_infection_ciphertexts.csv",
        "r"
    );
    if (dataset_file == NULL) {
        perror("results/scenario3_all_sboxes_infection_ciphertexts.csv");
        return 1;
    }
    if (fgets(line, sizeof(line), dataset_file) == NULL) {
        fputs("FAIL: public dataset is empty.\n", stderr);
        fclose(dataset_file);
        return 1;
    }

    while (fgets(line, sizeof(line), dataset_file) != NULL) {
        char *first_comma = strchr(line, ',');
        char *second_comma;
        char *ciphertext_text;
        char *newline;
        unsigned long target_sbox;
        uint8_t ciphertext[SCENERY_BLOCK_SIZE];

        if (first_comma == NULL) {
            fputs("FAIL: malformed public dataset row.\n", stderr);
            fclose(dataset_file);
            return 1;
        }
        *first_comma = '\0';
        target_sbox = strtoul(line, NULL, 10);
        second_comma = strchr(first_comma + 1, ',');
        if (second_comma == NULL || target_sbox >= SCENERY_ATTACK_SBOXES) {
            fputs("FAIL: malformed public dataset row.\n", stderr);
            fclose(dataset_file);
            return 1;
        }
        ciphertext_text = second_comma + 1;
        newline = strpbrk(ciphertext_text, "\r\n");
        if (newline != NULL) {
            *newline = '\0';
        }
        if (parse_block_hex(ciphertext_text, ciphertext) != 0 ||
            scenery_known_infection_full_add_ciphertext(
                &result,
                (uint8_t)target_sbox,
                ciphertext
            ) != 0) {
            fputs("FAIL: invalid public dataset row.\n", stderr);
            fclose(dataset_file);
            return 1;
        }
    }
    if (fclose(dataset_file) != 0) {
        perror("closing all-S-box infection dataset");
        return 1;
    }

    status = scenery_known_infection_recover_full_round_key(&result);
    if (status != 0 || !result.success) {
        fprintf(stderr,
                "FAIL: full minimum-frequency recovery returned %d (%zu/8 successful).\n",
                status,
                result.successful_sboxes);
        return 1;
    }

    /* Simulation ground truth is introduced only after the public attack. */
    if (scenery_init(&verification_ctx, key) != 0) {
        fputs("FAIL: verification context initialization failed.\n", stderr);
        return 1;
    }
    actual_sk28 = verification_ctx.round_keys[SCENERY_ROUNDS - 1u];

    histograms_file = fopen(
        "results/scenario3_all_sboxes_infection_histograms.csv",
        "w"
    );
    if (histograms_file == NULL) {
        perror("results/scenario3_all_sboxes_infection_histograms.csv");
        return 1;
    }
    fputs("target_sbox,value,count,is_minimum,is_theoretical_target\n",
          histograms_file);
    for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
        size_t value;
        const uint8_t actual_word = scenery_round_key_sbox_word(
            actual_sk28,
            (uint8_t)sbox
        );
        const uint8_t expected_minimum = (uint8_t)(delta ^ actual_word);
        for (value = 0u; value < SCENERY_ATTACK_DOMAIN; ++value) {
            fprintf(histograms_file,
                    "%zu,0x%zX,%" PRIu64 ",%u,%u\n",
                    sbox,
                    value,
                    result.per_sbox[sbox].histogram[value],
                    value == (size_t)result.per_sbox[sbox].minimum_value ? 1u : 0u,
                    value == (size_t)expected_minimum ? 1u : 0u);
        }
    }
    if (fclose(histograms_file) != 0) {
        perror("closing all-S-box infection histograms");
        return 1;
    }

    summary_file = fopen(
        "results/scenario3_full_sk28_recovery_summary.csv",
        "w"
    );
    if (summary_file == NULL) {
        perror("results/scenario3_full_sk28_recovery_summary.csv");
        return 1;
    }
    fputs("target_sbox,known_delta,sample_count,minimum_value,minimum_count,"
          "second_minimum_count,minimum_gap,minimum_multiplicity,recovered_word,"
          "actual_word,word_verified\n", summary_file);

    puts("Scenario 3 / Step 2B: complete Algorithm-3 SK28 recovery");
    puts("sbox  samples  min  min_count  second  gap  recovered  actual");
    for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
        const scenery_known_infection_result *word = &result.per_sbox[sbox];
        const uint8_t actual_word = scenery_round_key_sbox_word(
            actual_sk28,
            (uint8_t)sbox
        );
        const uint64_t gap = word->second_minimum_count - word->minimum_count;
        const int verified = word->recovered_round_key_word == actual_word;

        printf("%4zu  %7" PRIu64 "  0x%X  %9" PRIu64 "  %6" PRIu64
               "  %3" PRIu64 "     0x%X       0x%X\n",
               sbox,
               word->sample_count,
               word->minimum_value,
               word->minimum_count,
               word->second_minimum_count,
               gap,
               word->recovered_round_key_word,
               actual_word);
        fprintf(summary_file,
                "%zu,0x%X,%" PRIu64 ",0x%X,%" PRIu64 ",%" PRIu64
                ",%" PRIu64 ",%zu,0x%X,0x%X,%s\n",
                sbox,
                delta,
                word->sample_count,
                word->minimum_value,
                word->minimum_count,
                word->second_minimum_count,
                gap,
                word->minimum_multiplicity,
                word->recovered_round_key_word,
                actual_word,
                verified ? "PASS" : "FAIL");
    }
    fprintf(summary_file,
            "complete_sk28,,,,,,,,0x%08" PRIX32 ",0x%08" PRIX32 ",%s\n",
            result.recovered_round_key,
            actual_sk28,
            result.recovered_round_key == actual_sk28 ? "PASS" : "FAIL");
    if (fclose(summary_file) != 0) {
        perror("closing full SK28 infection summary");
        return 1;
    }

    printf("successful S-boxes:  %zu/8\n", result.successful_sboxes);
    printf("recovered SK28:      %08" PRIX32 "\n", result.recovered_round_key);
    printf("actual SK28:         %08" PRIX32 "\n", actual_sk28);
    puts("histograms CSV: results/scenario3_all_sboxes_infection_histograms.csv");
    puts("summary CSV:    results/scenario3_full_sk28_recovery_summary.csv");

    if (result.recovered_round_key != actual_sk28) {
        fputs("FAIL: recovered full SK28 does not match ground truth.\n", stderr);
        return 1;
    }
    puts("PASS: eight known-fault infection campaigns recovered the complete 32-bit SK28.");
    return 0;
}
