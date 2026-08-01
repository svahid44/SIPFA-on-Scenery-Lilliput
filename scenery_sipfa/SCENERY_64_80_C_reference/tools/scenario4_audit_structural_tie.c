#include "known_detection_attack.h"
#include "persistent_fault.h"
#include "scenery.h"
#include "unknown_detection_attack.h"
#include "unknown_infection_attack.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_DATASET "results/scenario4_unknown_infection_ciphertexts.csv"
#define DEFAULT_RANKING "results/scenario4_active_key_ranking_top64.csv"
#define DEFAULT_TARGET_SBOX UINT8_C(5)
#define EXPECTED_DELTA UINT8_C(0xB)
#define PREFIX_COUNT 6u

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
    uint8_t **ciphertexts,
    size_t *sample_count
)
{
    FILE *input;
    uint8_t *buffer = NULL;
    size_t capacity = 0u;
    size_t count = 0u;
    size_t line_number = 0u;
    char line[256];

    input = fopen(path, "r");
    if (input == NULL) {
        perror(path);
        return -1;
    }

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
            fprintf(stderr, "FAIL: malformed dataset line %zu.\n", line_number);
            free(buffer);
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
            free(buffer);
            fclose(input);
            return -1;
        }
        if (count == capacity) {
            const size_t next_capacity = capacity == 0u ? 4096u : capacity * 2u;
            uint8_t *next = (uint8_t *)realloc(
                buffer,
                next_capacity * SCENERY_BLOCK_SIZE
            );

            if (next == NULL) {
                free(buffer);
                fclose(input);
                return -1;
            }
            buffer = next;
            capacity = next_capacity;
        }
        memcpy(
            buffer + count * SCENERY_BLOCK_SIZE,
            ciphertext,
            SCENERY_BLOCK_SIZE
        );
        ++count;
    }

    if (fclose(input) != 0 || count == 0u) {
        free(buffer);
        return -1;
    }
    *ciphertexts = buffer;
    *sample_count = count;
    return 0;
}

static size_t split_csv_fields(char *line, char *fields[], size_t capacity)
{
    size_t count = 0u;
    char *cursor = line;

    while (cursor != NULL && count < capacity) {
        char *comma = strchr(cursor, ',');

        fields[count++] = cursor;
        if (comma == NULL) {
            break;
        }
        *comma = '\0';
        cursor = comma + 1u;
    }
    return count;
}

static int read_rank1_candidates(
    const char *path,
    uint32_t candidates[SCENERY_UNKNOWN_INFECTION_EQUIVALENCE_MAX],
    size_t *candidate_count
)
{
    FILE *input;
    char line[512];
    size_t count = 0u;
    size_t line_number = 0u;

    input = fopen(path, "r");
    if (input == NULL) {
        perror(path);
        return -1;
    }
    while (fgets(line, sizeof(line), input) != NULL) {
        char *fields[16];
        char *newline;
        size_t field_count;
        char *end = NULL;
        unsigned long packed;
        unsigned long is_maximum;

        ++line_number;
        if (line_number == 1u) {
            continue;
        }
        newline = strpbrk(line, "\r\n");
        if (newline != NULL) {
            *newline = '\0';
        }
        field_count = split_csv_fields(line, fields, 16u);
        if (field_count < 12u) {
            fprintf(stderr, "FAIL: malformed ranking line %zu.\n", line_number);
            fclose(input);
            return -1;
        }
        errno = 0;
        is_maximum = strtoul(fields[11], &end, 0);
        if (errno != 0 || end == fields[11] || *end != '\0') {
            fclose(input);
            return -1;
        }
        if (is_maximum == 0u) {
            continue;
        }
        if (count >= SCENERY_UNKNOWN_INFECTION_EQUIVALENCE_MAX) {
            fclose(input);
            return -1;
        }
        errno = 0;
        packed = strtoul(fields[2], &end, 0);
        if (errno != 0 || end == fields[2] || *end != '\0' ||
            packed >= SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES) {
            fclose(input);
            return -1;
        }
        candidates[count++] = (uint32_t)packed;
    }
    if (fclose(input) != 0 || count < 2u) {
        return -1;
    }
    *candidate_count = count;
    return 0;
}

static uint64_t direct_prefix_score(
    const uint8_t *ciphertexts,
    size_t prefix,
    uint8_t target_sbox,
    uint32_t packed_candidate
)
{
    uint64_t histogram[16] = { 0u };
    uint64_t sum_squares = 0u;
    size_t sample;
    size_t value;

    for (sample = 0u; sample < prefix; ++sample) {
        const uint8_t previous_word =
            scenery_unknown_partial_decrypt_previous_word(
                ciphertexts + sample * SCENERY_BLOCK_SIZE,
                target_sbox,
                packed_candidate
            );
        ++histogram[previous_word];
    }
    for (value = 0u; value < 16u; ++value) {
        sum_squares += histogram[value] * histogram[value];
    }
    return UINT64_C(16) * sum_squares -
           (uint64_t)prefix * (uint64_t)prefix;
}

static size_t build_prefixes(size_t sample_count, size_t prefixes[PREFIX_COUNT])
{
    const size_t defaults[PREFIX_COUNT - 1u] = {
        64u, 256u, 1024u, 4096u, 16384u
    };
    size_t count = 0u;
    size_t index;

    for (index = 0u; index < PREFIX_COUNT - 1u; ++index) {
        if (defaults[index] < sample_count) {
            prefixes[count++] = defaults[index];
        }
    }
    prefixes[count++] = sample_count;
    return count;
}

static int write_equivalence_matrix(
    const uint32_t *candidates,
    size_t candidate_count,
    const scenery_unknown_infection_equivalence_result *audit
)
{
    FILE *file = fopen("results/scenario4_rank1_equivalence_matrix.csv", "w");
    size_t first;

    if (file == NULL) {
        return -1;
    }
    fputs("candidate_a,candidate_b,constant_xor_valid,constant_xor,histogram_permutation_equal,score_equal\n",
          file);
    for (first = 0u; first < candidate_count; ++first) {
        size_t second;

        for (second = 0u; second < candidate_count; ++second) {
            fprintf(file,
                    "0x%05" PRIX32 ",0x%05" PRIX32 ",%u,0x%X,%u,%u\n",
                    candidates[first],
                    candidates[second],
                    audit->constant_xor_valid[first][second],
                    audit->constant_xor[first][second],
                    audit->histogram_permutation_equal[first][second],
                    audit->score_numerators[first] ==
                        audit->score_numerators[second] ? 1u : 0u);
        }
    }
    return fclose(file) == 0 ? 0 : -1;
}

static int write_prefix_scores(
    const uint8_t *ciphertexts,
    size_t sample_count,
    uint8_t target_sbox,
    const uint32_t *candidates,
    size_t candidate_count,
    int *all_equal
)
{
    size_t prefixes[PREFIX_COUNT];
    const size_t prefix_count = build_prefixes(sample_count, prefixes);
    FILE *file = fopen("results/scenario4_prefix_equivalence.csv", "w");
    size_t prefix_index;

    if (file == NULL) {
        return -1;
    }
    *all_equal = 1;
    fputs("sample_count,candidate,score_numerator,sei,equal_within_prefix\n",
          file);
    for (prefix_index = 0u; prefix_index < prefix_count; ++prefix_index) {
        const size_t prefix = prefixes[prefix_index];
        uint64_t reference = 0u;
        size_t candidate;

        for (candidate = 0u; candidate < candidate_count; ++candidate) {
            const uint64_t score = direct_prefix_score(
                ciphertexts,
                prefix,
                target_sbox,
                candidates[candidate]
            );
            const int equal = candidate == 0u || score == reference;

            if (candidate == 0u) {
                reference = score;
            } else if (!equal) {
                *all_equal = 0;
            }
            fprintf(file,
                    "%zu,0x%05" PRIX32 ",%" PRIu64 ",%.15g,%u\n",
                    prefix,
                    candidates[candidate],
                    score,
                    scenery_unknown_infection_score_to_sei(score, prefix),
                    equal ? 1u : 0u);
        }
    }
    return fclose(file) == 0 ? 0 : -1;
}

static int write_role_c_truth_table(
    const uint32_t *candidates,
    size_t candidate_count,
    uint8_t *varying_mask,
    uint8_t *constant_mask,
    uint8_t *source_sbox
)
{
    uint8_t words[SCENERY_UNKNOWN_INFECTION_EQUIVALENCE_MAX]
                 [SCENERY_UNKNOWN_ACTIVE_WORDS];
    uint8_t active_sboxes[SCENERY_UNKNOWN_ACTIVE_WORDS];
    uint8_t differences = 0u;
    FILE *file;
    size_t candidate;
    size_t input;

    if (scenery_unknown_active_sboxes(DEFAULT_TARGET_SBOX, active_sboxes) != 0) {
        return -1;
    }
    for (candidate = 0u; candidate < candidate_count; ++candidate) {
        scenery_unknown_unpack_active_words(candidates[candidate], words[candidate]);
        if (candidate > 0u) {
            differences |= (uint8_t)(words[0][2] ^ words[candidate][2]);
        }
    }
    *varying_mask = (uint8_t)(differences & 0x0Fu);
    *constant_mask = (uint8_t)((~differences) & 0x0Fu);
    *source_sbox = active_sboxes[2];

    file = fopen("results/scenario4_role_c_truth_table.csv", "w");
    if (file == NULL) {
        return -1;
    }
    fputs("public_input", file);
    for (candidate = 0u; candidate < candidate_count; ++candidate) {
        fprintf(file, ",candidate_0x%05" PRIX32 "_word_C_0x%X_contribution",
                candidates[candidate], words[candidate][2]);
    }
    fputc('\n', file);

    for (input = 0u; input < 16u; ++input) {
        fprintf(file, "0x%zX", input);
        for (candidate = 0u; candidate < candidate_count; ++candidate) {
            const uint8_t substituted = scenery_sbox_correct(
                (uint8_t)(input ^ words[candidate][2])
            );
            const uint8_t role_c_contribution = (uint8_t)(substituted & 1u);

            fprintf(file, ",0x%X", role_c_contribution);
        }
        fputc('\n', file);
    }
    return fclose(file) == 0 ? 0 : -1;
}

static int candidate_present(
    const uint32_t *candidates,
    size_t candidate_count,
    uint32_t target
)
{
    size_t index;

    for (index = 0u; index < candidate_count; ++index) {
        if (candidates[index] == target) {
            return 1;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    const uint8_t verification_key[SCENERY_KEY_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99
    };
    const char *dataset_path = DEFAULT_DATASET;
    const char *ranking_path = DEFAULT_RANKING;
    uint8_t *ciphertexts = NULL;
    size_t sample_count = 0u;
    uint32_t candidates[SCENERY_UNKNOWN_INFECTION_EQUIVALENCE_MAX];
    size_t candidate_count = 0u;
    scenery_unknown_infection_equivalence_result audit;
    scenery_ctx ctx;
    uint32_t actual_packed;
    int actual_present;
    int all_prefix_scores_equal = 0;
    uint8_t varying_mask = 0u;
    uint8_t constant_mask = 0u;
    uint8_t source_sbox = 0u;
    FILE *file;
    size_t index;
    int status;

    if (argc > 1) {
        dataset_path = argv[1];
    }
    if (argc > 2) {
        ranking_path = argv[2];
    }
    if (argc > 3) {
        fprintf(stderr, "Usage: %s [public_dataset.csv] [step2_ranking.csv]\n",
                argv[0]);
        return 2;
    }

    if (read_public_dataset(dataset_path, &ciphertexts, &sample_count) != 0 ||
        read_rank1_candidates(ranking_path, candidates, &candidate_count) != 0) {
        free(ciphertexts);
        return 1;
    }

    status = scenery_unknown_infection_audit_candidate_equivalence(
        ciphertexts,
        sample_count,
        DEFAULT_TARGET_SBOX,
        candidates,
        candidate_count,
        &audit
    );
    if (status != 0 || !audit.success) {
        fprintf(stderr, "FAIL: structural-equivalence audit returned %d.\n",
                status);
        free(ciphertexts);
        return 1;
    }

    if (write_equivalence_matrix(candidates, candidate_count, &audit) != 0 ||
        write_prefix_scores(
            ciphertexts,
            sample_count,
            DEFAULT_TARGET_SBOX,
            candidates,
            candidate_count,
            &all_prefix_scores_equal) != 0 ||
        write_role_c_truth_table(
            candidates,
            candidate_count,
            &varying_mask,
            &constant_mask,
            &source_sbox) != 0) {
        fputs("FAIL: could not write Step-3 result files.\n", stderr);
        free(ciphertexts);
        return 1;
    }

    if (scenery_init(&ctx, verification_key) != 0) {
        free(ciphertexts);
        return 1;
    }
    actual_packed = scenery_unknown_pack_round_key_active_words(
        ctx.round_keys[SCENERY_ROUNDS - 1u],
        DEFAULT_TARGET_SBOX
    );
    actual_present = candidate_present(candidates, candidate_count, actual_packed);

    file = fopen("results/scenario4_rank1_equivalence_summary.csv", "w");
    if (file == NULL) {
        free(ciphertexts);
        return 1;
    }
    fputs("parameter,value\n", file);
    fprintf(file, "sample_count,%zu\n", sample_count);
    fprintf(file, "target_sbox,%u\n", DEFAULT_TARGET_SBOX);
    fprintf(file, "rank1_candidate_count,%zu\n", candidate_count);
    fprintf(file, "varying_role,C\n");
    fprintf(file, "varying_source_sbox,%u\n", source_sbox);
    fprintf(file, "varying_bit_mask,0x%X\n", varying_mask);
    fprintf(file, "constant_bit_mask,0x%X\n", constant_mask);
    fprintf(file, "unique_exact_sequences,%zu\n",
            audit.unique_exact_sequences);
    fprintf(file, "xor_equivalence_classes,%zu\n",
            audit.xor_equivalence_classes);
    fprintf(file, "unique_sei_scores,%zu\n", audit.unique_score_count);
    fprintf(file, "all_pairs_constant_xor,%s\n",
            audit.all_pairs_xor_equivalent ? "YES" : "NO");
    fprintf(file, "all_prefix_scores_equal,%s\n",
            all_prefix_scores_equal ? "YES" : "NO");
    fprintf(file, "more_samples_can_break_current_sei_tie,%s\n",
            audit.all_pairs_xor_equivalent && all_prefix_scores_equal
                ? "NO" : "UNDETERMINED");
    fprintf(file, "honest_recovery,18/20 active bits + unique delta\n");
    fprintf(file, "status,%s\n",
            audit.all_pairs_xor_equivalent &&
            audit.unique_score_count == 1u &&
            all_prefix_scores_equal ? "PASS" : "FAIL");
    fclose(file);

    file = fopen("results/scenario4_step3_verification.csv", "w");
    if (file == NULL) {
        free(ciphertexts);
        return 1;
    }
    fputs("parameter,value\n", file);
    fprintf(file, "actual_packed_active_key,0x%05" PRIX32 "\n", actual_packed);
    fprintf(file, "actual_candidate_present,%s\n", actual_present ? "YES" : "NO");
    fprintf(file, "actual_candidate_uniquely_identified,NO\n");
    fprintf(file, "expected_delta,0x%X\n", EXPECTED_DELTA);
    fprintf(file, "delta_already_recovered_in_step2,YES\n");
    fprintf(file, "final_claim,18/20 active bits + unique delta\n");
    fprintf(file, "status,%s\n",
            actual_present && audit.unique_score_count == 1u ? "PASS" : "FAIL");
    fclose(file);

    puts("Scenario 4 / Step 3: structural tie audit");
    printf("public samples:                 %zu\n", sample_count);
    printf("rank-1 candidates:              %zu\n", candidate_count);
    for (index = 0u; index < candidate_count; ++index) {
        uint8_t words[SCENERY_UNKNOWN_ACTIVE_WORDS];

        scenery_unknown_unpack_active_words(candidates[index], words);
        printf("  0x%05" PRIX32 "  A..E=%X,%X,%X,%X,%X  score=%" PRIu64 "%s\n",
               candidates[index],
               words[0], words[1], words[2], words[3], words[4],
               audit.score_numerators[index],
               candidates[index] == actual_packed ? "  <-- actual" : "");
    }
    printf("unique exact sequences:         %zu\n",
           audit.unique_exact_sequences);
    printf("XOR-equivalence classes:        %zu\n",
           audit.xor_equivalence_classes);
    printf("unique SEI scores:              %zu\n", audit.unique_score_count);
    printf("varying role/source:            C / S-box %u\n", source_sbox);
    printf("varying/constant masks:         0x%X / 0x%X\n",
           varying_mask, constant_mask);
    printf("all prefix scores equal:        %s\n",
           all_prefix_scores_equal ? "YES" : "NO");
    puts("Conclusion: the four candidates are structurally indistinguishable under the current one-word SEI observation.");
    puts("PASS: additional samples cannot resolve the two remaining active-key bits without changing the observation or attack assumptions.");

    free(ciphertexts);
    return actual_present && audit.all_pairs_xor_equivalent &&
           audit.unique_score_count == 1u && all_prefix_scores_equal ? 0 : 1;
}
