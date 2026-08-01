#include "known_detection_attack.h"
#include "scenery.h"
#include "unknown_infection_attack.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_INPUT "results/scenario4_unknown_infection_ciphertexts.csv"
#define DEFAULT_EXPECTED_SBOX UINT64_C(5)
#define DEFAULT_EXPECTED_DELTA UINT64_C(0xB)

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

int main(int argc, char **argv)
{
    const uint8_t key[SCENERY_KEY_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99
    };
    const char *input_path = DEFAULT_INPUT;
    uint64_t expected_sbox_u64 = DEFAULT_EXPECTED_SBOX;
    uint64_t expected_delta_u64 = DEFAULT_EXPECTED_DELTA;
    uint8_t expected_sbox;
    uint8_t expected_delta;
    FILE *input;
    FILE *histogram_file;
    FILE *score_file;
    FILE *candidate_file;
    FILE *summary_file;
    FILE *verification_file;
    scenery_unknown_infection_result attack;
    scenery_ctx ctx;
    char line[256];
    size_t line_number = 0u;
    size_t sbox;
    uint8_t actual_word;
    uint8_t expected_minimum;
    int localization_match;
    int minimum_match;
    int actual_pair_match;
    int status;

    if (argc > 1) {
        input_path = argv[1];
    }
    if ((argc > 2 && parse_u64(argv[2], &expected_sbox_u64) != 0) ||
        (argc > 3 && parse_u64(argv[3], &expected_delta_u64) != 0) ||
        argc > 4 || expected_sbox_u64 >= 8u || expected_delta_u64 >= 16u) {
        fprintf(stderr,
                "Usage: %s [public_csv] [expected_sbox] [expected_delta]\n",
                argv[0]);
        return 2;
    }
    expected_sbox = (uint8_t)expected_sbox_u64;
    expected_delta = (uint8_t)expected_delta_u64;

    input = fopen(input_path, "r");
    if (input == NULL) {
        perror(input_path);
        return 1;
    }

    scenery_unknown_infection_result_init(&attack);
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
            scenery_unknown_infection_add_ciphertext(
                &attack,
                ciphertext) != 0) {
            fprintf(stderr, "FAIL: invalid ciphertext on line %zu.\n",
                    line_number);
            fclose(input);
            return 1;
        }
    }
    if (fclose(input) != 0) {
        perror("closing scenario4 public dataset");
        return 1;
    }

    status = scenery_unknown_infection_identify_fault(&attack);

    histogram_file = fopen(
        "results/scenario4_unknown_infection_histograms.csv",
        "w"
    );
    if (histogram_file == NULL) {
        perror("results/scenario4_unknown_infection_histograms.csv");
        return 1;
    }
    fputs("sbox,value,count,probability,is_lane_minimum,is_detected_lane\n",
          histogram_file);
    for (sbox = 0u; sbox < SCENERY_UNKNOWN_INFECTION_SBOXES; ++sbox) {
        size_t value;
        for (value = 0u; value < SCENERY_UNKNOWN_INFECTION_DOMAIN; ++value) {
            fprintf(histogram_file,
                    "%zu,0x%zX,%" PRIu64 ",%.12f,%u,%u\n",
                    sbox,
                    value,
                    attack.histogram[sbox][value],
                    attack.sample_count == 0u
                        ? 0.0
                        : (double)attack.histogram[sbox][value] /
                          (double)attack.sample_count,
                    value == (size_t)attack.minimum_value[sbox] ? 1u : 0u,
                    attack.success && attack.detected_sbox == sbox ? 1u : 0u);
        }
    }
    fclose(histogram_file);

    score_file = fopen("results/scenario4_fault_localization_scores.csv", "w");
    if (score_file == NULL) {
        perror("results/scenario4_fault_localization_scores.csv");
        return 1;
    }
    fputs("sbox,sei,rank,minimum_value,minimum_count,second_minimum_count,minimum_gap,minimum_multiplicity,is_detected\n",
          score_file);
    for (sbox = 0u; sbox < SCENERY_UNKNOWN_INFECTION_SBOXES; ++sbox) {
        const uint64_t gap =
            attack.second_minimum_count[sbox] >= attack.minimum_count[sbox]
                ? attack.second_minimum_count[sbox] -
                  attack.minimum_count[sbox]
                : 0u;
        fprintf(score_file,
                "%zu,%.12g,%zu,0x%X,%" PRIu64 ",%" PRIu64
                ",%" PRIu64 ",%zu,%u\n",
                sbox,
                attack.lane_sei[sbox],
                attack.lane_rank[sbox],
                attack.minimum_value[sbox],
                attack.minimum_count[sbox],
                attack.second_minimum_count[sbox],
                gap,
                attack.minimum_multiplicity[sbox],
                attack.success && attack.detected_sbox == sbox ? 1u : 0u);
    }
    fclose(score_file);

    candidate_file = fopen(
        "results/scenario4_delta_key_word_candidates.csv",
        "w"
    );
    if (candidate_file == NULL) {
        perror("results/scenario4_delta_key_word_candidates.csv");
        return 1;
    }
    fputs("candidate_index,delta_candidate,sk28_word_candidate,detected_sbox,public_minimum\n",
          candidate_file);
    if (attack.success) {
        size_t delta;
        for (delta = 0u;
             delta < SCENERY_UNKNOWN_INFECTION_CANDIDATES;
             ++delta) {
            fprintf(candidate_file,
                    "%zu,0x%zX,0x%X,%u,0x%X\n",
                    delta,
                    delta,
                    scenery_unknown_infection_key_word_candidate(
                        attack.detected_public_minimum,
                        (uint8_t)delta),
                    attack.detected_sbox,
                    attack.detected_public_minimum);
        }
    }
    fclose(candidate_file);

    summary_file = fopen(
        "results/scenario4_fault_localization_summary.csv",
        "w"
    );
    if (summary_file == NULL) {
        perror("results/scenario4_fault_localization_summary.csv");
        return 1;
    }
    fputs("parameter,value\n", summary_file);
    fprintf(summary_file, "sample_count,%" PRIu64 "\n", attack.sample_count);
    if (attack.success) {
        fprintf(summary_file, "detected_sbox,%u\n", attack.detected_sbox);
        fprintf(summary_file, "public_minimum,0x%X\n",
                attack.detected_public_minimum);
    } else {
        fputs("detected_sbox,AMBIGUOUS\n", summary_file);
        fputs("public_minimum,AMBIGUOUS\n", summary_file);
    }
    fprintf(summary_file, "best_sei,%.12g\n", attack.best_sei);
    fprintf(summary_file, "second_best_sei,%.12g\n",
            attack.second_best_sei);
    fprintf(summary_file, "sei_gap,%.12g\n", attack.sei_gap);
    fprintf(summary_file, "best_candidate_count,%zu\n",
            attack.best_candidate_count);
    fprintf(summary_file, "coupled_delta_key_candidates,%u\n",
            (unsigned int)SCENERY_UNKNOWN_INFECTION_CANDIDATES);
    fprintf(summary_file, "status,%s\n",
            attack.success ? "PASS" : "AMBIGUOUS");
    fclose(summary_file);

    if (scenery_init(&ctx, key) != 0) {
        fputs("FAIL: verification scenery_init failed.\n", stderr);
        return 1;
    }
    actual_word = scenery_round_key_sbox_word(
        ctx.round_keys[SCENERY_ROUNDS - 1u],
        expected_sbox
    );
    expected_minimum = (uint8_t)(expected_delta ^ actual_word);
    localization_match = attack.success &&
                         attack.detected_sbox == expected_sbox;
    minimum_match = attack.success &&
                    attack.detected_public_minimum == expected_minimum;
    actual_pair_match = attack.success &&
        scenery_unknown_infection_key_word_candidate(
            attack.detected_public_minimum,
            expected_delta) == actual_word;

    verification_file = fopen(
        "results/scenario4_step1_verification.csv",
        "w"
    );
    if (verification_file == NULL) {
        perror("results/scenario4_step1_verification.csv");
        return 1;
    }
    fputs("parameter,value\n", verification_file);
    fprintf(verification_file, "expected_sbox,%u\n", expected_sbox);
    fprintf(verification_file, "expected_delta,0x%X\n", expected_delta);
    fprintf(verification_file, "actual_sk28_word,0x%X\n", actual_word);
    fprintf(verification_file, "expected_public_minimum,0x%X\n",
            expected_minimum);
    fprintf(verification_file, "localization_match,%s\n",
            localization_match ? "YES" : "NO");
    fprintf(verification_file, "minimum_relation_match,%s\n",
            minimum_match ? "YES" : "NO");
    fprintf(verification_file, "actual_pair_retained,%s\n",
            actual_pair_match ? "YES" : "NO");
    fprintf(verification_file, "status,%s\n",
            localization_match && minimum_match && actual_pair_match
                ? "PASS" : "FAIL");
    fclose(verification_file);

    puts("Scenario 4 / Step 1B: Algorithm-4 SEI fault localization");
    printf("public dataset:           %s\n", input_path);
    printf("published samples:        %" PRIu64 "\n", attack.sample_count);
    puts("sbox  rank  SEI             minimum  minimum-count  gap");
    for (sbox = 0u; sbox < SCENERY_UNKNOWN_INFECTION_SBOXES; ++sbox) {
        const uint64_t gap =
            attack.second_minimum_count[sbox] >= attack.minimum_count[sbox]
                ? attack.second_minimum_count[sbox] -
                  attack.minimum_count[sbox]
                : 0u;
        printf("%4zu  %4zu  %.9g  0x%X       %6" PRIu64
               "        %6" PRIu64 "%s\n",
               sbox,
               attack.lane_rank[sbox],
               attack.lane_sei[sbox],
               attack.minimum_value[sbox],
               attack.minimum_count[sbox],
               gap,
               attack.success && attack.detected_sbox == sbox
                   ? "  <-- detected" : "");
    }
    if (attack.success) {
        printf("detected S-box:           %u\n", attack.detected_sbox);
        printf("public minimum:           0x%X\n",
               attack.detected_public_minimum);
        printf("best/second SEI:          %.12g / %.12g\n",
               attack.best_sei,
               attack.second_best_sei);
        printf("SEI gap:                  %.12g\n", attack.sei_gap);
        puts("remaining ambiguity:      16 coupled (delta, SK28 word) pairs");
        puts("relation:                 SK28_word = public_minimum XOR delta");
    }
    puts("histograms: results/scenario4_unknown_infection_histograms.csv");
    puts("scores:     results/scenario4_fault_localization_scores.csv");
    puts("candidates: results/scenario4_delta_key_word_candidates.csv");
    puts("summary:    results/scenario4_fault_localization_summary.csv");
    puts("verification: results/scenario4_step1_verification.csv");

    if (status != 0 || !attack.success) {
        fputs("FAIL: Algorithm-4 Step 1 did not produce a unique SEI location and minimum.\n",
              stderr);
        return 1;
    }
    if (!localization_match || !minimum_match || !actual_pair_match) {
        fputs("FAIL: simulation-only ground-truth verification failed.\n",
              stderr);
        return 1;
    }

    puts("PASS: the unknown faulty logical S-box was identified without exposing delta, the key, or event labels; the true pair remains among 16 coupled hypotheses.");
    return 0;
}
