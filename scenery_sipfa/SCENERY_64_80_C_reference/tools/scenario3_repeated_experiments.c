#include "detection_dataset.h"
#include "known_infection_attack.h"
#include "persistent_fault.h"
#include "scenery.h"

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define GRID_POINTS 12u
#define MAX_SAMPLES 32768u

static const size_t SAMPLE_GRID[GRID_POINTS] = {
    512u, 1024u, 1536u, 2048u, 3072u, 4096u,
    6144u, 8192u, 12288u, 16384u, 24576u, 32768u
};

typedef struct experiment_rng {
    uint64_t state;
} experiment_rng;

typedef struct campaign_snapshot {
    scenery_known_infection_result attack;
    uint64_t internal_ineffective_count;
    uint64_t internal_infected_count;
} campaign_snapshot;

static uint64_t splitmix64_next(experiment_rng *rng)
{
    uint64_t z;

    rng->state += UINT64_C(0x9E3779B97F4A7C15);
    z = rng->state;
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

static uint64_t splitmix64_state_next(uint64_t *state)
{
    experiment_rng rng;
    uint64_t value;

    rng.state = *state;
    value = splitmix64_next(&rng);
    *state = rng.state;
    return value;
}

static void random_bytes(experiment_rng *rng, uint8_t *output, size_t length)
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

static void random_block(uint64_t *state, uint8_t block[SCENERY_BLOCK_SIZE])
{
    const uint64_t value = splitmix64_state_next(state);
    size_t byte;

    for (byte = 0u; byte < SCENERY_BLOCK_SIZE; ++byte) {
        block[byte] = (uint8_t)(value >> (8u * byte));
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
    size_t index;
    for (index = 0u; index < length; ++index) {
        fprintf(file, "%02X", data[index]);
    }
}

static uint64_t campaign_seed(uint64_t trial_seed, size_t sbox)
{
    return trial_seed ^
        (UINT64_C(0xD1B54A32D192ED03) * (uint64_t)(sbox + 1u));
}

/*
 * Simulation-only campaign collector.  The attack state receives only the
 * public ciphertext.  Internal event counters are recorded separately and
 * are used exclusively for evaluation of the theoretical rate.
 */
static int collect_campaign_snapshots(
    const scenery_ctx *ctx,
    uint8_t delta,
    uint8_t sbox,
    uint64_t seed,
    campaign_snapshot snapshots[GRID_POINTS]
)
{
    const uint8_t correct_output = scenery_sbox_correct(delta);
    const uint8_t faulty_output = (uint8_t)((correct_output + 1u) & 0x0Fu);
    uint64_t plaintext_state = seed;
    uint64_t infection_state = seed ^ UINT64_C(0xD1B54A32D192ED03);
    uint64_t ineffective = 0u;
    uint64_t infected = 0u;
    scenery_known_infection_result running;
    size_t point = 0u;
    size_t sample;

    scenery_known_infection_result_init(&running, sbox, delta);
    scenery_fault_reset();
    if (scenery_fault_inject(sbox, delta, faulty_output) != 0) {
        return -1;
    }

    for (sample = 1u; sample <= MAX_SAMPLES; ++sample) {
        uint8_t plaintext[SCENERY_BLOCK_SIZE];
        uint8_t correct_ciphertext[SCENERY_BLOCK_SIZE];
        uint8_t faulty_ciphertext[SCENERY_BLOCK_SIZE];
        uint8_t public_ciphertext[SCENERY_BLOCK_SIZE];

        random_block(&plaintext_state, plaintext);
        if (scenery_encrypt_block(ctx, plaintext, correct_ciphertext) != 0 ||
            scenery_encrypt_block_faulty(ctx, plaintext, faulty_ciphertext) != 0) {
            scenery_fault_reset();
            return -2;
        }

        if (memcmp(correct_ciphertext, faulty_ciphertext, SCENERY_BLOCK_SIZE) == 0) {
            memcpy(public_ciphertext, correct_ciphertext, SCENERY_BLOCK_SIZE);
            ++ineffective;
        } else {
            random_block(&infection_state, public_ciphertext);
            ++infected;
        }

        if (scenery_known_infection_add_ciphertext(&running, public_ciphertext) != 0) {
            scenery_fault_reset();
            return -3;
        }

        if (point < GRID_POINTS && sample == SAMPLE_GRID[point]) {
            snapshots[point].attack = running;
            snapshots[point].internal_ineffective_count = ineffective;
            snapshots[point].internal_infected_count = infected;
            ++point;
        }
    }

    scenery_fault_reset();
    return point == GRID_POINTS ? 0 : -4;
}

static void write_trial_header(FILE *file)
{
    fputs(
        "trial,samples_per_sbox,master_seed,trial_seed,key,known_delta,"
        "actual_sk28,recovered_sk28,full_key_success,correct_words,"
        "unique_minimum_words,total_public_outputs,total_internal_ineffective,"
        "total_infected,aggregate_empirical_rate,theoretical_rate,"
        "absolute_rate_error,mean_minimum_gap,min_minimum_gap,max_minimum_gap\n",
        file
    );
}

static void write_word_header(FILE *file)
{
    fputs(
        "trial,samples_per_sbox,sbox,trial_seed,known_delta,minimum_value,"
        "minimum_count,second_minimum_count,minimum_gap,minimum_multiplicity,"
        "recovered_word,actual_word,unique_minimum,word_success,"
        "internal_ineffective,internal_infected,empirical_ineffective_rate\n",
        file
    );
}

int main(int argc, char **argv)
{
    size_t trials = 100u;
    uint64_t master_seed = UINT64_C(0x5343454E45525933);
    const char *trial_path = "results/scenario3_repeated_trials.csv";
    const char *word_path = "results/scenario3_repeated_words.csv";
    FILE *trial_file;
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
        trial_path = argv[3];
    }
    if (argc > 4) {
        word_path = argv[4];
    }

    trial_file = fopen(trial_path, "w");
    if (trial_file == NULL) {
        perror(trial_path);
        return 1;
    }
    word_file = fopen(word_path, "w");
    if (word_file == NULL) {
        perror(word_path);
        fclose(trial_file);
        return 1;
    }
    write_trial_header(trial_file);
    write_word_header(word_file);

    rng.state = master_seed;
    for (trial = 0u; trial < trials; ++trial) {
        uint8_t key[SCENERY_KEY_SIZE];
        uint8_t delta;
        uint64_t trial_seed;
        scenery_ctx ctx;
        uint32_t actual_round_key;
        campaign_snapshot campaigns[SCENERY_ATTACK_SBOXES][GRID_POINTS];
        size_t sbox;
        size_t point;

        random_bytes(&rng, key, sizeof(key));
        delta = (uint8_t)(splitmix64_next(&rng) & UINT64_C(0x0F));
        trial_seed = splitmix64_next(&rng);

        if (scenery_init(&ctx, key) != 0) {
            fputs("FAIL: scenery_init failed.\n", stderr);
            fclose(trial_file);
            fclose(word_file);
            return 1;
        }
        actual_round_key = ctx.round_keys[SCENERY_ROUNDS - 1u];

        for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
            if (collect_campaign_snapshots(
                    &ctx,
                    delta,
                    (uint8_t)sbox,
                    campaign_seed(trial_seed, sbox),
                    campaigns[sbox]) != 0) {
                fprintf(stderr, "FAIL: campaign collection failed at trial %zu, S-box %zu.\n", trial, sbox);
                fclose(trial_file);
                fclose(word_file);
                return 1;
            }
        }

        for (point = 0u; point < GRID_POINTS; ++point) {
            const size_t samples = SAMPLE_GRID[point];
            scenery_known_infection_full_result result;
            uint64_t total_ineffective = 0u;
            uint64_t total_infected = 0u;
            uint64_t gap_sum = 0u;
            uint64_t min_gap = UINT64_MAX;
            uint64_t max_gap = 0u;
            size_t correct_words = 0u;
            size_t unique_words = 0u;
            size_t recovered_words = 0u;
            int full_success;
            double empirical_rate;
            double absolute_error;

            scenery_known_infection_full_result_init(&result, delta);
            for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
                scenery_known_infection_result *word = &result.per_sbox[sbox];
                const uint8_t actual_word = scenery_round_key_sbox_word(
                    actual_round_key,
                    (uint8_t)sbox
                );
                const int recovery_status = scenery_known_infection_recover_word(
                    &(campaigns[sbox][point].attack)
                );

                *word = campaigns[sbox][point].attack;
                total_ineffective += campaigns[sbox][point].internal_ineffective_count;
                total_infected += campaigns[sbox][point].internal_infected_count;

                if (recovery_status == 0 && word->success) {
                    const uint64_t gap = word->second_minimum_count - word->minimum_count;
                    result.recovered_words[sbox] = word->recovered_round_key_word;
                    ++unique_words;
                    ++recovered_words;
                    gap_sum += gap;
                    if (gap < min_gap) {
                        min_gap = gap;
                    }
                    if (gap > max_gap) {
                        max_gap = gap;
                    }
                    if (word->recovered_round_key_word == actual_word) {
                        ++correct_words;
                    }
                }

                fprintf(
                    word_file,
                    "%zu,%zu,%zu,0x%016" PRIX64 ",0x%X,0x%X,%" PRIu64
                    ",%" PRIu64 ",%" PRIu64 ",%zu,0x%X,0x%X,%d,%d,%" PRIu64
                    ",%" PRIu64 ",%.12f\n",
                    trial,
                    samples,
                    sbox,
                    trial_seed,
                    delta,
                    word->minimum_value,
                    word->minimum_count,
                    word->second_minimum_count,
                    word->second_minimum_count - word->minimum_count,
                    word->minimum_multiplicity,
                    word->recovered_round_key_word,
                    actual_word,
                    recovery_status == 0 && word->minimum_multiplicity == 1u,
                    recovery_status == 0 && word->success &&
                        word->recovered_round_key_word == actual_word,
                    campaigns[sbox][point].internal_ineffective_count,
                    campaigns[sbox][point].internal_infected_count,
                    (double)campaigns[sbox][point].internal_ineffective_count /
                        (double)samples
                );
            }

            if (recovered_words == SCENERY_ATTACK_SBOXES) {
                result.recovered_round_key = scenery_compose_round_key_sbox_words(
                    result.recovered_words
                );
                result.success = 1;
                result.successful_sboxes = SCENERY_ATTACK_SBOXES;
            }

            full_success = result.success &&
                result.recovered_round_key == actual_round_key;
            empirical_rate = (double)total_ineffective /
                (double)(samples * SCENERY_ATTACK_SBOXES);
            absolute_error = empirical_rate > theoretical_rate
                ? empirical_rate - theoretical_rate
                : theoretical_rate - empirical_rate;
            if (min_gap == UINT64_MAX) {
                min_gap = 0u;
            }

            fprintf(trial_file, "%zu,%zu,0x%016" PRIX64 ",0x%016" PRIX64 ",",
                    trial, samples, master_seed, trial_seed);
            print_hex(trial_file, key, sizeof(key));
            fprintf(
                trial_file,
                ",0x%X,0x%08" PRIX32 ",0x%08" PRIX32
                ",%d,%zu,%zu,%zu,%" PRIu64 ",%" PRIu64
                ",%.12f,%.12f,%.12f,%.6f,%" PRIu64 ",%" PRIu64 "\n",
                delta,
                actual_round_key,
                result.recovered_round_key,
                full_success,
                correct_words,
                unique_words,
                samples * SCENERY_ATTACK_SBOXES,
                total_ineffective,
                total_infected,
                empirical_rate,
                theoretical_rate,
                absolute_error,
                recovered_words > 0u ? (double)gap_sum / (double)recovered_words : 0.0,
                min_gap,
                max_gap
            );
        }

        printf("completed trial %zu/%zu\n", trial + 1u, trials);
    }

    if (fclose(trial_file) != 0 || fclose(word_file) != 0) {
        fputs("FAIL: output close error.\n", stderr);
        return 1;
    }

    printf("raw trial CSV: %s\n", trial_path);
    printf("raw word CSV:  %s\n", word_path);
    printf("trials:        %zu\n", trials);
    printf("sample grid:   ");
    for (trial = 0u; trial < GRID_POINTS; ++trial) {
        printf("%zu%s", SAMPLE_GRID[trial], trial + 1u == GRID_POINTS ? "\n" : ",");
    }
    puts("PASS: repeated known-fault infection experiments completed.");
    return 0;
}
