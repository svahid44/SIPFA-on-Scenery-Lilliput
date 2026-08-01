#include "known_detection_attack.h"
#include "unknown_detection_attack.h"

#include <ctype.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_INPUT "results/scenario2_unknown_detection_ciphertexts.csv"
#define CANDIDATE_CAPACITY 65536u

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

static int read_public_dataset(
    const char *path,
    uint8_t **ciphertexts_out,
    size_t *sample_count_out,
    scenery_unknown_detection_result *localization
)
{
    FILE *input;
    uint8_t *ciphertexts = NULL;
    size_t count = 0u;
    size_t capacity = 0u;
    size_t line_number = 0u;
    char line[256];

    input = fopen(path, "r");
    if (input == NULL) {
        perror(path);
        return -1;
    }
    scenery_unknown_detection_result_init(localization);

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
            free(ciphertexts);
            fclose(input);
            return -1;
        }
        ++comma;
        newline = strpbrk(comma, "\r\n");
        if (newline != NULL) {
            *newline = '\0';
        }
        if (parse_ciphertext_hex(comma, ciphertext) != 0) {
            fprintf(stderr, "FAIL: invalid ciphertext on line %zu.\n",
                    line_number);
            free(ciphertexts);
            fclose(input);
            return -1;
        }
        if (count == capacity) {
            size_t new_capacity = capacity == 0u ? 512u : 2u * capacity;
            uint8_t *resized = (uint8_t *)realloc(
                ciphertexts,
                new_capacity * SCENERY_BLOCK_SIZE
            );
            if (resized == NULL) {
                fputs("FAIL: dataset allocation failed.\n", stderr);
                free(ciphertexts);
                fclose(input);
                return -1;
            }
            ciphertexts = resized;
            capacity = new_capacity;
        }
        memcpy(ciphertexts + count * SCENERY_BLOCK_SIZE,
               ciphertext, SCENERY_BLOCK_SIZE);
        ++count;
        if (scenery_unknown_detection_add_ciphertext(
                localization,
                ciphertext) != 0) {
            free(ciphertexts);
            fclose(input);
            return -1;
        }
    }
    if (fclose(input) != 0) {
        perror("closing public dataset");
        free(ciphertexts);
        return -1;
    }
    if (count == 0u) {
        fputs("FAIL: public dataset is empty.\n", stderr);
        free(ciphertexts);
        return -1;
    }
    *ciphertexts_out = ciphertexts;
    *sample_count_out = count;
    return 0;
}

static void print_missing_values(uint16_t mask)
{
    unsigned int value;
    int first = 1;

    for (value = 0u; value < 16u; ++value) {
        if ((mask & (uint16_t)(UINT16_C(1) << value)) != 0u) {
            printf("%s0x%X", first ? "" : "|", value);
            first = 0;
        }
    }
}

int main(int argc, char **argv)
{
    const char *input_path = DEFAULT_INPUT;
    uint8_t *ciphertexts = NULL;
    size_t sample_count = 0u;
    scenery_unknown_detection_result localization;
    scenery_unknown_partial_result partial;
    scenery_unknown_active_candidate *candidates;
    FILE *candidate_file;
    FILE *summary_file;
    FILE *consensus_file;
    FILE *histogram_file;
    size_t index;
    int status;

    if (argc > 1) {
        input_path = argv[1];
    }
    if (argc > 2) {
        fprintf(stderr, "Usage: %s [public_ciphertext_csv]\n", argv[0]);
        return 2;
    }

    if (read_public_dataset(
            input_path,
            &ciphertexts,
            &sample_count,
            &localization) != 0) {
        return 1;
    }
    if (scenery_unknown_detection_identify_fault(&localization) != 0 ||
        !localization.success) {
        fputs("FAIL: Step 1 did not identify one global missing value.\n",
              stderr);
        free(ciphertexts);
        return 1;
    }

    candidates = (scenery_unknown_active_candidate *)calloc(
        CANDIDATE_CAPACITY,
        sizeof(*candidates)
    );
    if (candidates == NULL) {
        fputs("FAIL: candidate allocation failed.\n", stderr);
        free(ciphertexts);
        return 1;
    }

    status = scenery_unknown_detection_filter_active_key_candidates(
        ciphertexts,
        sample_count,
        localization.detected_sbox,
        localization.detected_missing_value,
        candidates,
        CANDIDATE_CAPACITY,
        &partial
    );
    if (status != 0 || !partial.success ||
        partial.stored_candidate_count != partial.surviving_candidate_count) {
        fprintf(stderr,
                "FAIL: candidate filter status=%d survivors=%zu stored=%zu.\n",
                status,
                partial.surviving_candidate_count,
                partial.stored_candidate_count);
        free(candidates);
        free(ciphertexts);
        return 1;
    }

    candidate_file = fopen("results/scenario2_active_key_candidates.csv", "w");
    if (candidate_file == NULL) {
        perror("results/scenario2_active_key_candidates.csv");
        free(candidates);
        free(ciphertexts);
        return 1;
    }
    fputs("candidate_index,packed_active_words,word_A,word_B,word_C,word_D,word_E,missing_mask,missing_count,missing_values\n",
          candidate_file);
    for (index = 0u; index < partial.stored_candidate_count; ++index) {
        uint8_t words[SCENERY_UNKNOWN_ACTIVE_WORDS];
        unsigned int value;
        int first = 1;

        scenery_unknown_unpack_active_words(candidates[index].packed_words, words);
        fprintf(candidate_file,
                "%zu,0x%05" PRIX32 ",0x%X,0x%X,0x%X,0x%X,0x%X,0x%04X,%u,",
                index,
                candidates[index].packed_words,
                words[0], words[1], words[2], words[3], words[4],
                candidates[index].missing_mask,
                candidates[index].missing_count);
        for (value = 0u; value < 16u; ++value) {
            if ((candidates[index].missing_mask &
                 (uint16_t)(UINT16_C(1) << value)) != 0u) {
                fprintf(candidate_file, "%s0x%X", first ? "" : "|", value);
                first = 0;
            }
        }
        fputc('\n', candidate_file);
    }
    fclose(candidate_file);

    consensus_file = fopen("results/scenario2_active_key_consensus.csv", "w");
    if (consensus_file == NULL) {
        perror("results/scenario2_active_key_consensus.csv");
        free(candidates);
        free(ciphertexts);
        return 1;
    }
    fputs("role,source_sbox,known_bit_mask,known_bit_value,known_bits\n",
          consensus_file);
    for (index = 0u; index < SCENERY_UNKNOWN_ACTIVE_WORDS; ++index) {
        unsigned int bits = 0u;
        uint8_t mask = partial.known_bit_masks[index];
        while (mask != 0u) {
            bits += (unsigned int)(mask & 1u);
            mask = (uint8_t)(mask >> 1);
        }
        fprintf(consensus_file,
                "%c,%u,0x%X,0x%X,%u\n",
                (int)('A' + (int)index),
                partial.active_sboxes[index],
                partial.known_bit_masks[index],
                partial.known_bit_values[index],
                bits);
    }
    fclose(consensus_file);

    histogram_file = fopen(
        "results/scenario2_candidate_previous_round_histograms.csv",
        "w"
    );
    if (histogram_file == NULL) {
        perror("results/scenario2_candidate_previous_round_histograms.csv");
        free(candidates);
        free(ciphertexts);
        return 1;
    }
    fputs("candidate_index,packed_active_words,value,count,is_missing\n",
          histogram_file);
    for (index = 0u; index < partial.stored_candidate_count; ++index) {
        uint64_t histogram[16] = { 0u };
        size_t sample;
        unsigned int value;

        for (sample = 0u; sample < sample_count; ++sample) {
            const uint8_t previous_word =
                scenery_unknown_partial_decrypt_previous_word(
                    ciphertexts + sample * SCENERY_BLOCK_SIZE,
                    partial.target_sbox,
                    candidates[index].packed_words
                );
            ++histogram[previous_word];
        }
        for (value = 0u; value < 16u; ++value) {
            fprintf(histogram_file,
                    "%zu,0x%05" PRIX32 ",0x%X,%" PRIu64 ",%u\n",
                    index,
                    candidates[index].packed_words,
                    value,
                    histogram[value],
                    histogram[value] == 0u ? 1u : 0u);
        }
    }
    fclose(histogram_file);

    summary_file = fopen(
        "results/scenario2_partial_decryption_summary.csv",
        "w"
    );
    if (summary_file == NULL) {
        perror("results/scenario2_partial_decryption_summary.csv");
        free(candidates);
        free(ciphertexts);
        return 1;
    }
    fputs("parameter,value\n", summary_file);
    fprintf(summary_file, "sample_count,%zu\n", sample_count);
    fprintf(summary_file, "detected_sbox,%u\n", partial.target_sbox);
    fprintf(summary_file, "public_missing_value,0x%X\n",
            partial.public_missing_value);
    fprintf(summary_file, "active_role_A_sbox,%u\n", partial.active_sboxes[0]);
    fprintf(summary_file, "active_role_B_sbox,%u\n", partial.active_sboxes[1]);
    fprintf(summary_file, "active_role_C_sbox,%u\n", partial.active_sboxes[2]);
    fprintf(summary_file, "active_role_D_sbox,%u\n", partial.active_sboxes[3]);
    fprintf(summary_file, "active_role_E_sbox,%u\n", partial.active_sboxes[4]);
    fprintf(summary_file, "tested_candidates,%" PRIu32 "\n",
            partial.tested_candidates);
    fprintf(summary_file, "candidate_sample_evaluations,%" PRIu64 "\n",
            partial.candidate_sample_evaluations);
    fprintf(summary_file, "surviving_candidates,%zu\n",
            partial.surviving_candidate_count);
    fprintf(summary_file, "candidate_missing_pairs,%" PRIu64 "\n",
            partial.candidate_missing_pairs);
    fprintf(summary_file, "recovered_active_bits,%zu\n",
            partial.recovered_active_bits);
    fprintf(summary_file, "active_key_bits,20\n");
    fprintf(summary_file, "delta_recovered,%s\n",
            partial.delta_recovered ? "YES" : "NO");
    if (partial.delta_recovered) {
        fprintf(summary_file, "recovered_delta,0x%X\n",
                partial.recovered_delta);
    } else {
        fputs("recovered_delta,AMBIGUOUS\n", summary_file);
    }
    fprintf(summary_file, "status,%s\n", partial.success ? "PASS" : "FAIL");
    fclose(summary_file);

    puts("Scenario 2 / Step 2: Algorithm-2 partial-decryption candidate filter");
    printf("public dataset:             %s\n", input_path);
    printf("public ineffective samples: %zu\n", sample_count);
    printf("detected S-box:             %u\n", partial.target_sbox);
    printf("public missing value:       0x%X\n", partial.public_missing_value);
    printf("active S-box roles A..E:    %u,%u,%u,%u,%u\n",
           partial.active_sboxes[0], partial.active_sboxes[1],
           partial.active_sboxes[2], partial.active_sboxes[3],
           partial.active_sboxes[4]);
    printf("tested candidates:          %" PRIu32 "\n",
           partial.tested_candidates);
    printf("surviving candidates:       %zu\n",
           partial.surviving_candidate_count);
    puts("candidate  words(A,B,C,D,E)  missing-values");
    for (index = 0u; index < partial.stored_candidate_count; ++index) {
        uint8_t words[SCENERY_UNKNOWN_ACTIVE_WORDS];
        scenery_unknown_unpack_active_words(candidates[index].packed_words, words);
        printf("0x%05" PRIX32 "    %X,%X,%X,%X,%X          ",
               candidates[index].packed_words,
               words[0], words[1], words[2], words[3], words[4]);
        print_missing_values(candidates[index].missing_mask);
        putchar('\n');
    }
    puts("role  source-sbox  known-mask  known-value");
    for (index = 0u; index < SCENERY_UNKNOWN_ACTIVE_WORDS; ++index) {
        printf("  %c       %u          0x%X         0x%X\n",
               (int)('A' + (int)index),
               partial.active_sboxes[index],
               partial.known_bit_masks[index],
               partial.known_bit_values[index]);
    }
    printf("recovered active bits:      %zu/20\n",
           partial.recovered_active_bits);
    if (partial.delta_recovered) {
        printf("recovered secret delta:     0x%X\n", partial.recovered_delta);
    }
    puts("candidates: results/scenario2_active_key_candidates.csv");
    puts("consensus:  results/scenario2_active_key_consensus.csv");
    puts("histograms: results/scenario2_candidate_previous_round_histograms.csv");
    puts("summary:    results/scenario2_partial_decryption_summary.csv");

    free(candidates);
    free(ciphertexts);

    if (partial.surviving_candidate_count == 0u) {
        fputs("FAIL: no active-key candidate preserved a missing value.\n", stderr);
        return 1;
    }
    puts("PASS: partial decryption filtered the 2^20 active-key space using the round-27 missing-value criterion.");
    return 0;
}
