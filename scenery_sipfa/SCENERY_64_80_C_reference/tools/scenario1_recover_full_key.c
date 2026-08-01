#include "known_detection_attack.h"
#include "scenery.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_DATASET "results/scenario1_all_sboxes_ineffective.csv"
#define DEFAULT_HISTOGRAM "results/scenario1_all_sboxes_histograms.csv"
#define DEFAULT_SUMMARY "results/scenario1_full_sk28_summary.csv"

static int parse_u8(const char *text, uint8_t *value)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0' || parsed > 255u) {
        return -1;
    }
    *value = (uint8_t)parsed;
    return 0;
}

static int parse_hex_block(
    const char *text,
    uint8_t output[SCENERY_BLOCK_SIZE]
)
{
    size_t index;

    if (text == NULL || strlen(text) != SCENERY_BLOCK_SIZE * 2u) {
        return -1;
    }
    for (index = 0u; index < SCENERY_BLOCK_SIZE; ++index) {
        char byte_text[3];
        char *end = NULL;
        unsigned long value;

        byte_text[0] = text[index * 2u];
        byte_text[1] = text[index * 2u + 1u];
        byte_text[2] = '\0';
        errno = 0;
        value = strtoul(byte_text, &end, 16);
        if (errno != 0 || end != byte_text + 2 || value > 255u) {
            return -1;
        }
        output[index] = (uint8_t)value;
    }
    return 0;
}

static int load_dataset(
    const char *path,
    scenery_known_detection_full_result *result
)
{
    FILE *file = fopen(path, "r");
    char line[512];
    uint64_t rows = 0u;

    if (file == NULL) {
        perror(path);
        return -1;
    }
    if (fgets(line, sizeof(line), file) == NULL) {
        fclose(file);
        return -1;
    }

    while (fgets(line, sizeof(line), file) != NULL) {
        unsigned int target_sbox;
        uint64_t query_index;
        uint64_t ineffective_index;
        char plaintext_hex[SCENERY_BLOCK_SIZE * 2u + 1u];
        char ciphertext_hex[SCENERY_BLOCK_SIZE * 2u + 1u];
        uint8_t ciphertext[SCENERY_BLOCK_SIZE];
        int fields;

        fields = sscanf(
            line,
            "%u,%" SCNu64 ",%" SCNu64 ",%16[^,],%16s",
            &target_sbox,
            &query_index,
            &ineffective_index,
            plaintext_hex,
            ciphertext_hex
        );
        (void)query_index;
        (void)ineffective_index;
        (void)plaintext_hex;
        if (fields != 5 || target_sbox >= SCENERY_ATTACK_SBOXES ||
            parse_hex_block(ciphertext_hex, ciphertext) != 0 ||
            scenery_known_detection_full_add_ciphertext(
                result,
                (uint8_t)target_sbox,
                ciphertext) != 0) {
            fprintf(stderr, "FAIL: malformed dataset row after line %" PRIu64 ".\n",
                    rows + 1u);
            fclose(file);
            return -1;
        }
        ++rows;
    }

    if (ferror(file)) {
        fclose(file);
        return -1;
    }
    if (fclose(file) != 0) {
        return -1;
    }
    return rows == 0u ? -1 : 0;
}

static int write_histograms(
    const char *path,
    const scenery_known_detection_full_result *result
)
{
    FILE *file = fopen(path, "w");
    size_t sbox;

    if (file == NULL) {
        perror(path);
        return -1;
    }
    fputs("target_sbox,value,count,is_missing\n", file);
    for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
        size_t value;
        for (value = 0u; value < SCENERY_ATTACK_DOMAIN; ++value) {
            fprintf(file, "%zu,%zu,%" PRIu64 ",%u\n",
                    sbox,
                    value,
                    result->per_sbox[sbox].histogram[value],
                    result->per_sbox[sbox].histogram[value] == 0u ? 1u : 0u);
        }
    }
    return fclose(file) == 0 ? 0 : -1;
}

static int write_summary(
    const char *path,
    const scenery_known_detection_full_result *result,
    uint8_t known_delta,
    uint32_t actual_round_key,
    int verified
)
{
    FILE *file = fopen(path, "w");
    size_t sbox;

    if (file == NULL) {
        perror(path);
        return -1;
    }
    fputs("target_sbox,known_delta,sample_count,missing_count,missing_value,"
          "recovered_word,actual_word,word_verified\n", file);
    for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
        const scenery_known_detection_result *word = &result->per_sbox[sbox];
        const uint8_t actual_word = scenery_round_key_sbox_word(
            actual_round_key,
            (uint8_t)sbox
        );
        fprintf(file,
                "%zu,0x%X,%" PRIu64 ",%zu,0x%X,0x%X,0x%X,%s\n",
                sbox,
                known_delta,
                word->sample_count,
                word->missing_count,
                word->missing_count == 1u ? word->missing_values[0] : 0u,
                result->recovered_words[sbox],
                actual_word,
                result->recovered_words[sbox] == actual_word ? "PASS" : "FAIL");
    }
    fprintf(file, "complete_sk28,,,,,0x%08" PRIX32 ",0x%08" PRIX32 ",%s\n",
            result->recovered_round_key,
            actual_round_key,
            verified ? "PASS" : "FAIL");
    return fclose(file) == 0 ? 0 : -1;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s [dataset.csv] [known_delta] [histograms.csv] [summary.csv]\n",
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
    uint8_t known_delta = 0x5u;
    scenery_known_detection_full_result result;
    scenery_ctx verification_ctx;
    uint32_t actual_round_key;
    int recovery_status;
    int verified;
    size_t sbox;

    if (argc > 1) {
        dataset_path = argv[1];
    }
    if (argc > 2 && parse_u8(argv[2], &known_delta) != 0) {
        usage(argv[0]);
        return 2;
    }
    if (argc > 3) {
        histogram_path = argv[3];
    }
    if (argc > 4) {
        summary_path = argv[4];
    }
    if (argc > 5 || known_delta >= SCENERY_ATTACK_DOMAIN) {
        usage(argv[0]);
        return 2;
    }

    scenery_known_detection_full_result_init(&result, known_delta);
    if (load_dataset(dataset_path, &result) != 0) {
        return 1;
    }
    recovery_status = scenery_known_detection_recover_full_round_key(&result);

    /* Ground truth is created only after the attack has finished. */
    if (scenery_init(&verification_ctx, key) != 0) {
        fputs("FAIL: verification context initialization failed.\n", stderr);
        return 1;
    }
    actual_round_key = verification_ctx.round_keys[SCENERY_ROUNDS - 1u];
    verified = recovery_status == 0 && result.success &&
        result.recovered_round_key == actual_round_key;

    puts("Scenario 1 / Step 4B: complete Algorithm-1 SK28 recovery");
    printf("dataset:             %s\n", dataset_path);
    printf("known delta:         0x%X\n", known_delta);
    puts("sbox  samples  missing  recovered_word  actual_word");
    for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
        const uint8_t actual_word = scenery_round_key_sbox_word(
            actual_round_key,
            (uint8_t)sbox
        );
        printf("%4zu  %7" PRIu64 "  0x%X      0x%X             0x%X\n",
               sbox,
               result.per_sbox[sbox].sample_count,
               result.per_sbox[sbox].missing_count == 1u
                   ? result.per_sbox[sbox].missing_values[0]
                   : 0u,
               result.recovered_words[sbox],
               actual_word);
    }
    printf("successful S-boxes:  %zu/%u\n",
           result.successful_sboxes, SCENERY_ATTACK_SBOXES);
    printf("recovered SK28:      %08" PRIX32 "\n",
           result.recovered_round_key);
    printf("actual SK28:         %08" PRIX32 "\n", actual_round_key);
    printf("histograms CSV:      %s\n", histogram_path);
    printf("summary CSV:         %s\n", summary_path);

    if (write_histograms(histogram_path, &result) != 0 ||
        write_summary(summary_path, &result, known_delta,
                      actual_round_key, verified) != 0) {
        return 1;
    }

    if (!verified) {
        fputs("FAIL: complete SK28 recovery was not uniquely verified.\n", stderr);
        return 1;
    }
    puts("PASS: eight known-fault campaigns recovered the complete 32-bit SK28.");
    return 0;
}
