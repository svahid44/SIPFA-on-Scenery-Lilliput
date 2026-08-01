#include "known_detection_attack.h"
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

#define DEFAULT_INPUT "results/scenario4_unknown_infection_ciphertexts.csv"
#define DEFAULT_EXPECTED_SBOX UINT64_C(5)
#define DEFAULT_EXPECTED_DELTA UINT64_C(0xB)
#define TOP_STORE_CAPACITY 64u
#define RANKING_ROWS 64u

typedef struct ranking_entry {
    uint32_t packed_words;
    uint64_t score_numerator;
} ranking_entry;

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

static int ranking_compare(const void *left, const void *right)
{
    const ranking_entry *a = (const ranking_entry *)left;
    const ranking_entry *b = (const ranking_entry *)right;

    if (a->score_numerator > b->score_numerator) {
        return -1;
    }
    if (a->score_numerator < b->score_numerator) {
        return 1;
    }
    if (a->packed_words < b->packed_words) {
        return -1;
    }
    if (a->packed_words > b->packed_words) {
        return 1;
    }
    return 0;
}

static int read_public_dataset(
    const char *path,
    uint8_t **ciphertexts,
    size_t *sample_count,
    scenery_unknown_infection_result *localization
)
{
    FILE *input;
    uint8_t *buffer = NULL;
    size_t capacity = 0u;
    size_t count = 0u;
    size_t line_number = 0u;
    char line[256];

    if (path == NULL || ciphertexts == NULL || sample_count == NULL ||
        localization == NULL) {
        return -1;
    }

    input = fopen(path, "r");
    if (input == NULL) {
        perror(path);
        return -1;
    }

    scenery_unknown_infection_result_init(localization);
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
            uint8_t *next;

            if (next_capacity >
                (size_t)SCENERY_UNKNOWN_INFECTION_MAX_SAMPLES) {
                fputs("FAIL: public dataset exceeds supported sample limit.\n",
                      stderr);
                free(buffer);
                fclose(input);
                return -1;
            }
            next = (uint8_t *)realloc(
                buffer,
                next_capacity * SCENERY_BLOCK_SIZE
            );
            if (next == NULL) {
                fputs("FAIL: ciphertext allocation failed.\n", stderr);
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
        if (scenery_unknown_infection_add_ciphertext(
                localization,
                ciphertext) != 0) {
            free(buffer);
            fclose(input);
            return -1;
        }
    }

    if (fclose(input) != 0) {
        perror("closing scenario4 public dataset");
        free(buffer);
        return -1;
    }
    if (count == 0u) {
        fputs("FAIL: public dataset is empty.\n", stderr);
        free(buffer);
        return -1;
    }

    *ciphertexts = buffer;
    *sample_count = count;
    return 0;
}

static unsigned int popcount4(uint8_t value)
{
    unsigned int count = 0u;

    value &= 0x0Fu;
    while (value != 0u) {
        count += (unsigned int)(value & 1u);
        value = (uint8_t)(value >> 1);
    }
    return count;
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
    uint8_t *ciphertexts = NULL;
    size_t sample_count = 0u;
    uint64_t *scores = NULL;
    ranking_entry *ranking = NULL;
    scenery_unknown_infection_active_candidate top[TOP_STORE_CAPACITY];
    scenery_unknown_infection_result localization;
    scenery_unknown_infection_partial_result partial;
    scenery_ctx ctx;
    uint32_t actual_packed;
    uint8_t actual_words[SCENERY_UNKNOWN_ACTIVE_WORDS];
    size_t actual_rank = 0u;
    size_t actual_tie_count = 0u;
    int actual_in_maximum = 0;
    int actual_consensus_match = 1;
    int delta_match;
    FILE *file;
    size_t index;
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

    if (read_public_dataset(
            input_path,
            &ciphertexts,
            &sample_count,
            &localization) != 0) {
        return 1;
    }
    status = scenery_unknown_infection_identify_fault(&localization);
    if (status != 0 || !localization.success) {
        fputs("FAIL: Step 1 did not produce a unique fault location/minimum.\n",
              stderr);
        free(ciphertexts);
        return 1;
    }

    scores = (uint64_t *)calloc(
        (size_t)SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES,
        sizeof(*scores)
    );
    ranking = (ranking_entry *)malloc(
        (size_t)SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES *
            sizeof(*ranking)
    );
    if (scores == NULL || ranking == NULL) {
        fputs("FAIL: ranking allocation failed.\n", stderr);
        free(ciphertexts);
        free(scores);
        free(ranking);
        return 1;
    }
    memset(top, 0, sizeof(top));

    status = scenery_unknown_infection_rank_active_key_candidates(
        ciphertexts,
        sample_count,
        localization.detected_sbox,
        localization.detected_public_minimum,
        scores,
        (size_t)SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES,
        top,
        TOP_STORE_CAPACITY,
        &partial
    );
    if (status != 0 || !partial.success) {
        fprintf(stderr,
                "FAIL: full candidate ranking returned %d (success=%d).\n",
                status,
                partial.success);
        free(ciphertexts);
        free(scores);
        free(ranking);
        return 1;
    }

    for (index = 0u;
         index < (size_t)SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES;
         ++index) {
        ranking[index].packed_words = (uint32_t)index;
        ranking[index].score_numerator = scores[index];
    }
    qsort(
        ranking,
        (size_t)SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES,
        sizeof(*ranking),
        ranking_compare
    );

    if (scenery_init(&ctx, key) != 0) {
        fputs("FAIL: verification scenery_init failed.\n", stderr);
        free(ciphertexts);
        free(scores);
        free(ranking);
        return 1;
    }
    actual_packed = scenery_unknown_pack_round_key_active_words(
        ctx.round_keys[SCENERY_ROUNDS - 1u],
        expected_sbox
    );
    scenery_unknown_unpack_active_words(actual_packed, actual_words);

    for (index = 0u;
         index < (size_t)SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES;
         ++index) {
        if (ranking[index].packed_words == actual_packed) {
            const uint64_t actual_score = ranking[index].score_numerator;
            size_t prior;

            actual_rank = 1u;
            for (prior = 0u; prior < index; ++prior) {
                if (ranking[prior].score_numerator > actual_score) {
                    ++actual_rank;
                }
            }
            actual_tie_count = 0u;
            for (prior = 0u;
                 prior < (size_t)SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES;
                 ++prior) {
                if (ranking[prior].score_numerator == actual_score) {
                    ++actual_tie_count;
                }
            }
            actual_in_maximum = actual_score == partial.top_score_numerator;
            break;
        }
    }
    for (index = 0u; index < SCENERY_UNKNOWN_ACTIVE_WORDS; ++index) {
        if ((actual_words[index] & partial.known_bit_masks[index]) !=
            partial.known_bit_values[index]) {
            actual_consensus_match = 0;
        }
    }
    delta_match = partial.delta_recovered &&
                  partial.recovered_delta == expected_delta;

    file = fopen("results/scenario4_active_key_ranking_top64.csv", "w");
    if (file == NULL) {
        perror("results/scenario4_active_key_ranking_top64.csv");
        free(ciphertexts);
        free(scores);
        free(ranking);
        return 1;
    }
    fputs("position,rank,packed_active_words,word_A,word_B,word_C,word_D,word_E,delta_candidate,score_numerator,sei,is_maximum,is_actual\n",
          file);
    {
        size_t displayed = RANKING_ROWS;
        size_t current_rank = 1u;
        uint64_t previous_score = ranking[0].score_numerator;

        if (displayed >
            (size_t)SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES) {
            displayed =
                (size_t)SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES;
        }
        for (index = 0u; index < displayed; ++index) {
            uint8_t words[SCENERY_UNKNOWN_ACTIVE_WORDS];
            uint8_t delta_candidate;

            if (index > 0u &&
                ranking[index].score_numerator != previous_score) {
                current_rank = index + 1u;
                previous_score = ranking[index].score_numerator;
            }
            scenery_unknown_unpack_active_words(
                ranking[index].packed_words,
                words
            );
            delta_candidate = (uint8_t)(
                partial.public_minimum ^ words[1]
            );
            fprintf(file,
                    "%zu,%zu,0x%05" PRIX32
                    ",0x%X,0x%X,0x%X,0x%X,0x%X,0x%X,%" PRIu64
                    ",%.12g,%u,%u\n",
                    index + 1u,
                    current_rank,
                    ranking[index].packed_words,
                    words[0], words[1], words[2], words[3], words[4],
                    delta_candidate,
                    ranking[index].score_numerator,
                    scenery_unknown_infection_score_to_sei(
                        ranking[index].score_numerator,
                        sample_count
                    ),
                    ranking[index].score_numerator ==
                        partial.top_score_numerator ? 1u : 0u,
                    ranking[index].packed_words == actual_packed ? 1u : 0u);
        }
    }
    fclose(file);

    file = fopen("results/scenario4_active_key_consensus.csv", "w");
    if (file == NULL) {
        perror("results/scenario4_active_key_consensus.csv");
        free(ciphertexts);
        free(scores);
        free(ranking);
        return 1;
    }
    fputs("role,source_sbox,known_bit_mask,known_bit_value,known_bits\n", file);
    for (index = 0u; index < SCENERY_UNKNOWN_ACTIVE_WORDS; ++index) {
        fprintf(file,
                "%c,%u,0x%X,0x%X,%u\n",
                (int)('A' + (int)index),
                partial.active_sboxes[index],
                partial.known_bit_masks[index],
                partial.known_bit_values[index],
                popcount4(partial.known_bit_masks[index]));
    }
    fclose(file);

    file = fopen("results/scenario4_partial_decryption_summary.csv", "w");
    if (file == NULL) {
        perror("results/scenario4_partial_decryption_summary.csv");
        free(ciphertexts);
        free(scores);
        free(ranking);
        return 1;
    }
    fputs("parameter,value\n", file);
    fprintf(file, "sample_count,%zu\n", partial.sample_count);
    fprintf(file, "detected_sbox,%u\n", partial.target_sbox);
    fprintf(file, "public_minimum,0x%X\n", partial.public_minimum);
    fprintf(file, "active_role_A_sbox,%u\n", partial.active_sboxes[0]);
    fprintf(file, "active_role_B_sbox,%u\n", partial.active_sboxes[1]);
    fprintf(file, "active_role_C_sbox,%u\n", partial.active_sboxes[2]);
    fprintf(file, "active_role_D_sbox,%u\n", partial.active_sboxes[3]);
    fprintf(file, "active_role_E_sbox,%u\n", partial.active_sboxes[4]);
    fprintf(file, "tested_candidates,%" PRIu32 "\n",
            partial.tested_candidates);
    fprintf(file, "walsh_masks_evaluated,%" PRIu32 "\n",
            partial.walsh_masks_evaluated);
    fprintf(file, "top_candidate_count,%zu\n",
            partial.top_candidate_count);
    fprintf(file, "top_score_numerator,%" PRIu64 "\n",
            partial.top_score_numerator);
    fprintf(file, "second_score_numerator,%" PRIu64 "\n",
            partial.second_score_numerator);
    fprintf(file, "top_sei,%.12g\n", partial.top_sei);
    fprintf(file, "second_sei,%.12g\n", partial.second_sei);
    fprintf(file, "sei_gap,%.12g\n", partial.sei_gap);
    fprintf(file, "recovered_active_bits,%zu\n",
            partial.recovered_active_bits);
    fputs("active_key_bits,20\n", file);
    fprintf(file, "delta_recovered,%s\n",
            partial.delta_recovered ? "YES" : "NO");
    if (partial.delta_recovered) {
        fprintf(file, "recovered_delta,0x%X\n", partial.recovered_delta);
    } else {
        fputs("recovered_delta,AMBIGUOUS\n", file);
    }
    fputs("structural_ambiguity,4 equivalent candidates\n", file);
    fprintf(file, "status,%s\n", partial.success ? "PASS" : "FAIL");
    fclose(file);

    file = fopen("results/scenario4_step2_verification.csv", "w");
    if (file == NULL) {
        perror("results/scenario4_step2_verification.csv");
        free(ciphertexts);
        free(scores);
        free(ranking);
        return 1;
    }
    fputs("parameter,value\n", file);
    fprintf(file, "expected_sbox,%u\n", expected_sbox);
    fprintf(file, "expected_delta,0x%X\n", expected_delta);
    fprintf(file, "actual_packed_active_key,0x%05" PRIX32 "\n",
            actual_packed);
    fprintf(file, "actual_candidate_rank,%zu\n", actual_rank);
    fprintf(file, "actual_score_tie_count,%zu\n", actual_tie_count);
    fprintf(file, "actual_candidate_in_maximum,%s\n",
            actual_in_maximum ? "YES" : "NO");
    fprintf(file, "actual_consensus_match,%s\n",
            actual_consensus_match ? "YES" : "NO");
    fprintf(file, "delta_match,%s\n", delta_match ? "YES" : "NO");
    fprintf(file, "honest_recovery,18/20 bits + unique delta\n");
    fprintf(file, "status,%s\n",
            localization.detected_sbox == expected_sbox &&
            actual_in_maximum && actual_consensus_match && delta_match &&
            partial.recovered_active_bits == 18u &&
            partial.top_candidate_count == 4u
                ? "PASS" : "FAIL");
    fclose(file);

    puts("Scenario 4 / Step 2: exact 2^20 partial-decryption SEI ranking");
    printf("public dataset:             %s\n", input_path);
    printf("public infection samples:   %zu\n", sample_count);
    printf("detected S-box:             %u\n", partial.target_sbox);
    printf("public minimum:             0x%X\n", partial.public_minimum);
    printf("active S-box roles A..E:    %u,%u,%u,%u,%u\n",
           partial.active_sboxes[0], partial.active_sboxes[1],
           partial.active_sboxes[2], partial.active_sboxes[3],
           partial.active_sboxes[4]);
    printf("tested candidates:          %" PRIu32 "\n",
           partial.tested_candidates);
    printf("Walsh masks evaluated:      %" PRIu32 "\n",
           partial.walsh_masks_evaluated);
    printf("rank-1 structural ties:     %zu\n",
           partial.top_candidate_count);
    puts("candidate  words(A,B,C,D,E)  delta  SEI");
    for (index = 0u; index < partial.stored_top_candidate_count; ++index) {
        uint8_t words[SCENERY_UNKNOWN_ACTIVE_WORDS];
        const uint8_t delta_candidate = (uint8_t)(
            partial.public_minimum ^
            ((top[index].packed_words >> 4u) & 0x0Fu)
        );

        scenery_unknown_unpack_active_words(top[index].packed_words, words);
        printf("0x%05" PRIX32 "    %X,%X,%X,%X,%X          0x%X   %.12g%s\n",
               top[index].packed_words,
               words[0], words[1], words[2], words[3], words[4],
               delta_candidate,
               top[index].sei,
               top[index].packed_words == actual_packed
                   ? "  <-- actual" : "");
    }
    printf("top/second SEI:             %.12g / %.12g\n",
           partial.top_sei,
           partial.second_sei);
    printf("SEI gap:                    %.12g\n", partial.sei_gap);
    printf("known masks A..E:           %X,%X,%X,%X,%X\n",
           partial.known_bit_masks[0], partial.known_bit_masks[1],
           partial.known_bit_masks[2], partial.known_bit_masks[3],
           partial.known_bit_masks[4]);
    printf("recovered active key bits:  %zu/20\n",
           partial.recovered_active_bits);
    printf("recovered delta:            0x%X\n",
           partial.recovered_delta);
    printf("actual candidate rank:      %zu (tie count %zu)\n",
           actual_rank,
           actual_tie_count);
    puts("ranking:     results/scenario4_active_key_ranking_top64.csv");
    puts("consensus:   results/scenario4_active_key_consensus.csv");
    puts("summary:     results/scenario4_partial_decryption_summary.csv");
    puts("verification: results/scenario4_step2_verification.csv");

    free(ciphertexts);
    free(scores);
    free(ranking);

    if (localization.detected_sbox != expected_sbox ||
        !actual_in_maximum || !actual_consensus_match || !delta_match ||
        partial.recovered_active_bits != 18u ||
        partial.top_candidate_count != 4u) {
        fputs("FAIL: simulation-only ground-truth verification failed.\n",
              stderr);
        return 1;
    }

    puts("PASS: full-space Algorithm-4 ranking recovered 18/20 active SK28 bits and the unique unknown delta; four MixColumns-equivalent candidates remain.");
    return 0;
}
