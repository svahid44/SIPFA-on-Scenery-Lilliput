#include "detection_dataset.h"
#include "known_detection_attack.h"
#include "persistent_fault.h"
#include "scenery.h"

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GRID_POINTS 15u
#define MAX_SAMPLES 256u
#define MAX_QUERIES_PER_CAMPAIGN UINT64_C(1000000)

static const size_t SAMPLE_GRID[GRID_POINTS] = {
    16u, 24u, 32u, 40u, 48u,
    56u, 64u, 72u, 80u, 96u,
    112u, 128u, 160u, 192u, 256u
};

typedef struct campaign_buffer {
    uint8_t ciphertexts[MAX_SAMPLES][SCENERY_BLOCK_SIZE];
    uint64_t query_at_sample[MAX_SAMPLES];
    size_t count;
} campaign_buffer;

typedef struct experiment_rng {
    uint64_t state;
} experiment_rng;

static uint64_t splitmix64_next(experiment_rng *rng)
{
    uint64_t z;

    rng->state += UINT64_C(0x9E3779B97F4A7C15);
    z = rng->state;
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

static void random_bytes(
    experiment_rng *rng,
    uint8_t *output,
    size_t length
)
{
    size_t offset = 0u;

    while (offset < length) {
        const uint64_t value = splitmix64_next(rng);
        unsigned int byte;
        for (byte = 0u; byte < 8u && offset < length; ++byte, ++offset) {
            output[offset] = (uint8_t)(value >> (8u * byte));
        }
    }
}

static int parse_size(const char *text, size_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    errno = 0;
    parsed = strtoull(text, &end, 0);
    if (errno != 0 || end == text || *end != '\0' || parsed == 0u ||
        parsed > (unsigned long long)SIZE_MAX) {
        return -1;
    }
    *value = (size_t)parsed;
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

static void print_hex(FILE *file, const uint8_t *data, size_t length)
{
    size_t i;
    for (i = 0u; i < length; ++i) {
        fprintf(file, "%02X", data[i]);
    }
}

static int store_ineffective(
    uint64_t query_index,
    uint64_t ineffective_index,
    const uint8_t plaintext[SCENERY_BLOCK_SIZE],
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    void *user_data
)
{
    campaign_buffer *buffer = (campaign_buffer *)user_data;
    const size_t index = (size_t)(ineffective_index - 1u);

    (void)plaintext;

    if (buffer == NULL || ineffective_index == 0u || index >= MAX_SAMPLES) {
        return -1;
    }
    memcpy(buffer->ciphertexts[index], ciphertext, SCENERY_BLOCK_SIZE);
    buffer->query_at_sample[index] = query_index;
    buffer->count = index + 1u;
    return 0;
}

static uint64_t campaign_seed(uint64_t trial_seed, size_t sbox)
{
    return trial_seed ^
        (UINT64_C(0xD1B54A32D192ED03) * (uint64_t)(sbox + 1u));
}

static int collect_campaign(
    const scenery_ctx *ctx,
    uint8_t delta,
    uint8_t sbox,
    uint64_t seed,
    campaign_buffer *buffer,
    scenery_detection_stats *stats
)
{
    const uint8_t correct_output = scenery_sbox_correct(delta);
    const uint8_t faulty_output = (uint8_t)((correct_output + 1u) & 0x0Fu);
    int status;

    memset(buffer, 0, sizeof(*buffer));
    scenery_fault_reset();
    if (scenery_fault_inject(sbox, delta, faulty_output) != 0) {
        return -1;
    }

    status = scenery_detection_collect(
        ctx,
        MAX_SAMPLES,
        MAX_QUERIES_PER_CAMPAIGN,
        seed,
        stats,
        store_ineffective,
        buffer
    );
    scenery_fault_reset();

    if (status != 0 || buffer->count != MAX_SAMPLES) {
        return -2;
    }
    return 0;
}

static size_t count_correct_words(
    const scenery_known_detection_full_result *result,
    uint32_t actual_round_key
)
{
    size_t sbox;
    size_t count = 0u;

    for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
        const uint8_t actual_word = scenery_round_key_sbox_word(
            actual_round_key,
            (uint8_t)sbox
        );
        if (result->per_sbox[sbox].success &&
            result->per_sbox[sbox].recovered_round_key_word == actual_word) {
            ++count;
        }
    }
    return count;
}

static void write_raw_header(FILE *file)
{
    fputs(
        "trial,samples_per_sbox,master_seed,trial_seed,key,known_delta,"
        "actual_sk28,recovered_sk28,full_key_success,correct_words,"
        "unique_missing_words,total_queries,mean_queries_per_sbox,"
        "min_queries_per_sbox,max_queries_per_sbox,aggregate_empirical_rate,"
        "theoretical_rate,absolute_rate_error\n",
        file
    );
}

static void write_word_header(FILE *file)
{
    fputs(
        "trial,samples_per_sbox,sbox,trial_seed,known_delta,query_count,"
        "empirical_rate,missing_count,missing_value,recovered_word,"
        "actual_word,unique_missing,word_success\n",
        file
    );
}

int main(int argc, char **argv)
{
    size_t trials = 100u;
    uint64_t master_seed = UINT64_C(0x5343454E45525931);
    const char *raw_path = "results/scenario1_repeated_trials.csv";
    const char *word_path = "results/scenario1_repeated_words.csv";
    FILE *raw_file;
    FILE *word_file;
    experiment_rng rng;
    size_t trial;
    const double theoretical_rate =
        scenery_detection_theoretical_ineffective_rate();

    if ((argc > 1 && parse_size(argv[1], &trials) != 0) ||
        (argc > 2 && parse_u64(argv[2], &master_seed) != 0) ||
        argc > 5) {
        fprintf(
            stderr,
            "Usage: %s [trials] [master_seed] [raw_trials.csv] [raw_words.csv]\n",
            argv[0]
        );
        return 2;
    }
    if (argc > 3) {
        raw_path = argv[3];
    }
    if (argc > 4) {
        word_path = argv[4];
    }

    raw_file = fopen(raw_path, "w");
    if (raw_file == NULL) {
        perror(raw_path);
        return 1;
    }
    word_file = fopen(word_path, "w");
    if (word_file == NULL) {
        perror(word_path);
        fclose(raw_file);
        return 1;
    }
    write_raw_header(raw_file);
    write_word_header(word_file);

    rng.state = master_seed;

    for (trial = 0u; trial < trials; ++trial) {
        uint8_t key[SCENERY_KEY_SIZE];
        uint8_t delta;
        uint64_t trial_seed;
        scenery_ctx ctx;
        uint32_t actual_round_key;
        campaign_buffer campaigns[SCENERY_ATTACK_SBOXES];
        scenery_detection_stats campaign_stats[SCENERY_ATTACK_SBOXES];
        size_t sbox;
        size_t point;

        random_bytes(&rng, key, sizeof(key));
        delta = (uint8_t)(splitmix64_next(&rng) & UINT64_C(0x0F));
        trial_seed = splitmix64_next(&rng);

        if (scenery_init(&ctx, key) != 0) {
            fputs("FAIL: scenery_init failed.\n", stderr);
            fclose(raw_file);
            fclose(word_file);
            return 1;
        }
        actual_round_key = ctx.round_keys[SCENERY_ROUNDS - 1u];

        for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
            if (collect_campaign(
                    &ctx,
                    delta,
                    (uint8_t)sbox,
                    campaign_seed(trial_seed, sbox),
                    &campaigns[sbox],
                    &campaign_stats[sbox]) != 0) {
                fprintf(
                    stderr,
                    "FAIL: campaign collection failed at trial %zu, S-box %zu.\n",
                    trial,
                    sbox
                );
                fclose(raw_file);
                fclose(word_file);
                return 1;
            }
        }

        for (point = 0u; point < GRID_POINTS; ++point) {
            const size_t samples = SAMPLE_GRID[point];
            scenery_known_detection_full_result result;
            uint64_t total_queries = 0u;
            uint64_t min_queries = UINT64_MAX;
            uint64_t max_queries = 0u;
            size_t unique_missing_words = 0u;
            size_t correct_words;
            int recovery_status;
            int full_success;
            double empirical_rate;
            double absolute_error;

            scenery_known_detection_full_result_init(&result, delta);
            for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
                size_t sample;
                const uint64_t queries = campaigns[sbox].query_at_sample[
                    samples - 1u
                ];

                total_queries += queries;
                if (queries < min_queries) {
                    min_queries = queries;
                }
                if (queries > max_queries) {
                    max_queries = queries;
                }

                for (sample = 0u; sample < samples; ++sample) {
                    if (scenery_known_detection_full_add_ciphertext(
                            &result,
                            (uint8_t)sbox,
                            campaigns[sbox].ciphertexts[sample]) != 0) {
                        fputs("FAIL: attack input accumulation failed.\n", stderr);
                        fclose(raw_file);
                        fclose(word_file);
                        return 1;
                    }
                }
            }

            recovery_status = scenery_known_detection_recover_full_round_key(
                &result
            );
            correct_words = count_correct_words(&result, actual_round_key);
            for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
                if (result.per_sbox[sbox].missing_count == 1u) {
                    ++unique_missing_words;
                }
            }
            full_success = recovery_status == 0 && result.success &&
                result.recovered_round_key == actual_round_key;
            empirical_rate =
                (double)(samples * SCENERY_ATTACK_SBOXES) /
                (double)total_queries;
            absolute_error = empirical_rate > theoretical_rate
                ? empirical_rate - theoretical_rate
                : theoretical_rate - empirical_rate;

            fprintf(raw_file, "%zu,%zu,0x%016" PRIX64 ",0x%016" PRIX64 ",",
                    trial, samples, master_seed, trial_seed);
            print_hex(raw_file, key, sizeof(key));
            fprintf(
                raw_file,
                ",0x%X,0x%08" PRIX32 ",0x%08" PRIX32
                ",%d,%zu,%zu,%" PRIu64 ",%.6f,%" PRIu64
                ",%" PRIu64 ",%.12f,%.12f,%.12f\n",
                delta,
                actual_round_key,
                result.recovered_round_key,
                full_success,
                correct_words,
                unique_missing_words,
                total_queries,
                (double)total_queries / (double)SCENERY_ATTACK_SBOXES,
                min_queries,
                max_queries,
                empirical_rate,
                theoretical_rate,
                absolute_error
            );

            for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
                const scenery_known_detection_result *word =
                    &result.per_sbox[sbox];
                const uint8_t actual_word = scenery_round_key_sbox_word(
                    actual_round_key,
                    (uint8_t)sbox
                );
                const uint64_t queries = campaigns[sbox].query_at_sample[
                    samples - 1u
                ];
                const double rate = (double)samples / (double)queries;
                const int unique_missing = word->missing_count == 1u;
                const int word_success = word->success &&
                    word->recovered_round_key_word == actual_word;
                const unsigned int missing_value = unique_missing
                    ? (unsigned int)word->missing_values[0]
                    : 255u;

                fprintf(
                    word_file,
                    "%zu,%zu,%zu,0x%016" PRIX64 ",0x%X,%" PRIu64
                    ",%.12f,%zu,",
                    trial,
                    samples,
                    sbox,
                    trial_seed,
                    delta,
                    queries,
                    rate,
                    word->missing_count
                );
                if (unique_missing) {
                    fprintf(word_file, "0x%X", missing_value);
                } else {
                    fputs("NA", word_file);
                }
                fprintf(
                    word_file,
                    ",0x%X,0x%X,%d,%d\n",
                    word->recovered_round_key_word,
                    actual_word,
                    unique_missing,
                    word_success
                );
            }
        }

        printf("completed trial %zu/%zu\n", trial + 1u, trials);
    }

    if (fclose(raw_file) != 0 || fclose(word_file) != 0) {
        fputs("FAIL: output close error.\n", stderr);
        return 1;
    }

    printf("raw trial CSV: %s\n", raw_path);
    printf("raw word CSV:  %s\n", word_path);
    printf("trials:        %zu\n", trials);
    printf("sample grid:   ");
    for (trial = 0u; trial < GRID_POINTS; ++trial) {
        printf("%zu%s", SAMPLE_GRID[trial],
               trial + 1u == GRID_POINTS ? "\n" : ",");
    }
    puts("PASS: repeated known-fault experiments completed.");
    return 0;
}
