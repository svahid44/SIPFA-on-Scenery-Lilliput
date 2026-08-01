#include "detection_dataset.h"
#include "known_detection_attack.h"
#include "persistent_fault.h"
#include "scenery.h"
#include "unknown_detection_attack.h"

#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define GRID_POINTS 9u
#define MAX_SAMPLES 512u
#define MAX_QUERIES UINT64_C(100000)

static const size_t SAMPLE_GRID[GRID_POINTS] = {
    64u, 96u, 128u, 160u, 192u, 256u, 320u, 384u, 512u
};

typedef struct experiment_rng {
    uint64_t state;
} experiment_rng;

typedef struct campaign_buffer {
    uint8_t ciphertexts[MAX_SAMPLES][SCENERY_BLOCK_SIZE];
    uint64_t query_at_sample[MAX_SAMPLES];
    size_t count;
} campaign_buffer;

static uint64_t splitmix64_next(experiment_rng *rng)
{
    uint64_t z;

    rng->state += UINT64_C(0x9E3779B97F4A7C15);
    z = rng->state;
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
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

static int collect_campaign(
    const scenery_ctx *ctx,
    uint8_t secret_sbox,
    uint8_t secret_delta,
    uint64_t seed,
    campaign_buffer *buffer,
    scenery_detection_stats *stats
)
{
    const uint8_t correct_output = scenery_sbox_correct(secret_delta);
    const uint8_t faulty_output = (uint8_t)((correct_output + 1u) & 0x0Fu);
    int status;

    memset(buffer, 0, sizeof(*buffer));
    scenery_fault_reset();
    if (scenery_fault_inject(secret_sbox, secret_delta, faulty_output) != 0) {
        return -1;
    }
    status = scenery_detection_collect(
        ctx,
        MAX_SAMPLES,
        MAX_QUERIES,
        seed,
        stats,
        store_ineffective,
        buffer
    );
    scenery_fault_reset();

    return status == 0 && buffer->count == MAX_SAMPLES ? 0 : -2;
}

static int consensus_matches_actual(
    const scenery_unknown_prefix_profile *profile,
    uint32_t actual_packed
)
{
    uint8_t actual_words[SCENERY_UNKNOWN_ACTIVE_WORDS];
    size_t role;

    scenery_unknown_unpack_active_words(actual_packed, actual_words);
    for (role = 0u; role < SCENERY_UNKNOWN_ACTIVE_WORDS; ++role) {
        if ((actual_words[role] & profile->known_bit_masks[role]) !=
            profile->known_bit_values[role]) {
            return 0;
        }
    }
    return 1;
}

static int candidate_survives_prefix(
    const campaign_buffer *campaign,
    size_t samples,
    uint8_t target_sbox,
    uint32_t packed_candidate
)
{
    uint16_t seen_mask = UINT16_C(0);
    size_t sample;

    for (sample = 0u; sample < samples; ++sample) {
        const uint8_t value = scenery_unknown_partial_decrypt_previous_word(
            campaign->ciphertexts[sample],
            target_sbox,
            packed_candidate
        );
        seen_mask |= (uint16_t)(UINT16_C(1) << value);
        if (seen_mask == UINT16_C(0xFFFF)) {
            return 0;
        }
    }
    return 1;
}

static void write_trial_header(FILE *file)
{
    fputs(
        "trial,samples,master_seed,trial_seed,key,secret_sbox,secret_delta,"
        "actual_sk28,actual_active_key,expected_public_missing,total_queries,"
        "empirical_rate,theoretical_rate,global_missing_count,detected_sbox,"
        "detected_missing,localization_success,filter_executed,tested_candidates,"
        "candidate_sample_evaluations,surviving_candidates,actual_candidate_present,"
        "recovered_active_bits,consensus_correct,delta_recovered,recovered_delta,"
        "delta_success,target_outcome_success,estimated_filter_cpu_seconds\n",
        file
    );
}

static void write_role_header(FILE *file)
{
    fputs(
        "trial,samples,filter_executed,role,source_sbox,known_mask,known_value,"
        "actual_word,known_bits,consensus_correct\n",
        file
    );
}

int main(int argc, char **argv)
{
    size_t trials = 100u;
    uint64_t master_seed = UINT64_C(0x5343454E45525932);
    const char *trial_path = "results/scenario2_repeated_trials.csv";
    const char *role_path = "results/scenario2_repeated_roles.csv";
    FILE *trial_file;
    FILE *role_file;
    experiment_rng rng;
    const double theoretical_rate =
        scenery_detection_theoretical_ineffective_rate();
    size_t trial;

    if ((argc > 1 && parse_size(argv[1], &trials) != 0) ||
        (argc > 2 && parse_u64(argv[2], &master_seed) != 0) || argc > 5) {
        fprintf(
            stderr,
            "Usage: %s [trials] [master_seed] [trial_csv] [role_csv]\n",
            argv[0]
        );
        return 2;
    }
    if (argc > 3) {
        trial_path = argv[3];
    }
    if (argc > 4) {
        role_path = argv[4];
    }

    trial_file = fopen(trial_path, "w");
    if (trial_file == NULL) {
        perror(trial_path);
        return 1;
    }
    role_file = fopen(role_path, "w");
    if (role_file == NULL) {
        perror(role_path);
        fclose(trial_file);
        return 1;
    }

    write_trial_header(trial_file);
    write_role_header(role_file);
    rng.state = master_seed;

    for (trial = 0u; trial < trials; ++trial) {
        uint8_t key[SCENERY_KEY_SIZE];
        const uint8_t secret_sbox =
            (uint8_t)(splitmix64_next(&rng) & UINT64_C(7));
        const uint8_t secret_delta =
            (uint8_t)(splitmix64_next(&rng) & UINT64_C(0x0F));
        const uint64_t trial_seed = splitmix64_next(&rng);
        scenery_ctx ctx;
        campaign_buffer campaign;
        scenery_detection_stats stats;
        scenery_unknown_detection_result max_identification;
        scenery_unknown_prefix_profile profiles[GRID_POINTS];
        uint8_t active_sboxes[SCENERY_UNKNOWN_ACTIVE_WORDS] = {0u};
        uint32_t actual_sk28;
        uint32_t actual_active_key;
        uint8_t actual_words[SCENERY_UNKNOWN_ACTIVE_WORDS];
        uint8_t actual_target_word;
        uint8_t expected_missing;
        int profile_available = 0;
        double profile_cpu_seconds = 0.0;
        size_t point;

        random_bytes(&rng, key, sizeof(key));
        if (scenery_init(&ctx, key) != 0) {
            fputs("FAIL: scenery_init failed.\n", stderr);
            fclose(trial_file);
            fclose(role_file);
            return 1;
        }
        actual_sk28 = ctx.round_keys[SCENERY_ROUNDS - 1u];
        actual_active_key = scenery_unknown_pack_round_key_active_words(
            actual_sk28,
            secret_sbox
        );
        scenery_unknown_unpack_active_words(actual_active_key, actual_words);
        actual_target_word = scenery_round_key_sbox_word(
            actual_sk28,
            secret_sbox
        );
        expected_missing = (uint8_t)(secret_delta ^ actual_target_word);

        if (collect_campaign(
                &ctx,
                secret_sbox,
                secret_delta,
                trial_seed,
                &campaign,
                &stats) != 0) {
            fprintf(stderr, "FAIL: collection failed at trial %zu.\n", trial);
            fclose(trial_file);
            fclose(role_file);
            return 1;
        }

        scenery_unknown_detection_result_init(&max_identification);
        for (point = 0u; point < MAX_SAMPLES; ++point) {
            if (scenery_unknown_detection_add_ciphertext(
                    &max_identification,
                    campaign.ciphertexts[point]) != 0) {
                fputs("FAIL: maximum-prefix identification failed.\n", stderr);
                fclose(trial_file);
                fclose(role_file);
                return 1;
            }
        }
        if (scenery_unknown_detection_identify_fault(&max_identification) == 0 &&
            max_identification.detected_sbox == secret_sbox &&
            max_identification.detected_missing_value == expected_missing) {
            clock_t start_clock;
            clock_t end_clock;
            int profile_status;

            start_clock = clock();
            profile_status = scenery_unknown_detection_profile_prefixes(
                &campaign.ciphertexts[0][0],
                SAMPLE_GRID,
                GRID_POINTS,
                max_identification.detected_sbox,
                max_identification.detected_missing_value,
                profiles
            );
            end_clock = clock();
            if (profile_status != 0) {
                fprintf(stderr, "FAIL: prefix profiler returned %d.\n", profile_status);
                fclose(trial_file);
                fclose(role_file);
                return 1;
            }
            profile_cpu_seconds = (double)(end_clock - start_clock) /
                (double)CLOCKS_PER_SEC;
            profile_available = 1;
            (void)scenery_unknown_active_sboxes(secret_sbox, active_sboxes);
        } else {
            memset(profiles, 0, sizeof(profiles));
        }

        for (point = 0u; point < GRID_POINTS; ++point) {
            const size_t samples = SAMPLE_GRID[point];
            scenery_unknown_detection_result identification;
            const scenery_unknown_prefix_profile *profile = &profiles[point];
            const uint64_t total_queries = campaign.query_at_sample[samples - 1u];
            const double empirical_rate = (double)samples / (double)total_queries;
            int identify_status;
            int localization_success;
            int filter_executed = 0;
            int actual_present = 0;
            int consensus_correct = 0;
            int delta_success = 0;
            int target_success = 0;
            double estimated_seconds = 0.0;
            size_t sample;
            size_t role;

            scenery_unknown_detection_result_init(&identification);
            for (sample = 0u; sample < samples; ++sample) {
                if (scenery_unknown_detection_add_ciphertext(
                        &identification,
                        campaign.ciphertexts[sample]) != 0) {
                    fputs("FAIL: identification accumulation failed.\n", stderr);
                    fclose(trial_file);
                    fclose(role_file);
                    return 1;
                }
            }
            identify_status = scenery_unknown_detection_identify_fault(
                &identification
            );
            localization_success = identify_status == 0 &&
                identification.detected_sbox == secret_sbox &&
                identification.detected_missing_value == expected_missing;

            if (localization_success && profile_available) {
                const uint64_t maximum_evaluations =
                    profiles[GRID_POINTS - 1u].candidate_sample_evaluations;

                filter_executed = 1;
                actual_present = candidate_survives_prefix(
                    &campaign,
                    samples,
                    secret_sbox,
                    actual_active_key
                );
                consensus_correct = consensus_matches_actual(
                    profile,
                    actual_active_key
                );
                delta_success = profile->delta_recovered &&
                    profile->recovered_delta == secret_delta;
                target_success = actual_present && consensus_correct &&
                    profile->recovered_active_bits == 18u &&
                    profile->surviving_candidate_count == 4u && delta_success;
                if (maximum_evaluations > 0u) {
                    estimated_seconds = profile_cpu_seconds *
                        (double)profile->candidate_sample_evaluations /
                        (double)maximum_evaluations;
                }
            }

            fprintf(
                trial_file,
                "%zu,%zu,0x%016" PRIX64 ",0x%016" PRIX64 ",",
                trial,
                samples,
                master_seed,
                trial_seed
            );
            print_hex(trial_file, key, sizeof(key));
            fprintf(
                trial_file,
                ",%u,0x%X,0x%08" PRIX32 ",0x%05" PRIX32 ",0x%X,"
                "%" PRIu64 ",%.12f,%.12f,%zu,",
                secret_sbox,
                secret_delta,
                actual_sk28,
                actual_active_key,
                expected_missing,
                total_queries,
                empirical_rate,
                theoretical_rate,
                identification.total_missing_count
            );
            if (identify_status == 0) {
                fprintf(
                    trial_file,
                    "%u,0x%X,",
                    identification.detected_sbox,
                    identification.detected_missing_value
                );
            } else {
                fputs("NA,NA,", trial_file);
            }
            fprintf(
                trial_file,
                "%d,%d,%" PRIu32 ",%" PRIu64 ",%zu,%d,%zu,%d,%d,",
                localization_success,
                filter_executed,
                filter_executed ? profile->tested_candidates : UINT32_C(0),
                filter_executed ? profile->candidate_sample_evaluations : UINT64_C(0),
                filter_executed ? profile->surviving_candidate_count : 0u,
                actual_present,
                filter_executed ? profile->recovered_active_bits : 0u,
                consensus_correct,
                filter_executed ? profile->delta_recovered : 0
            );
            if (filter_executed && profile->delta_recovered) {
                fprintf(trial_file, "0x%X,", profile->recovered_delta);
            } else {
                fputs("NA,", trial_file);
            }
            fprintf(
                trial_file,
                "%d,%d,%.6f\n",
                delta_success,
                target_success,
                estimated_seconds
            );

            for (role = 0u; role < SCENERY_UNKNOWN_ACTIVE_WORDS; ++role) {
                const uint8_t mask = filter_executed
                    ? profile->known_bit_masks[role] : 0u;
                const uint8_t value = filter_executed
                    ? profile->known_bit_values[role] : 0u;
                const unsigned int known_bits = popcount4(mask);
                const int role_correct = filter_executed &&
                    (actual_words[role] & mask) == value;

                fprintf(
                    role_file,
                    "%zu,%zu,%d,%zu,%u,0x%X,0x%X,0x%X,%u,%d\n",
                    trial,
                    samples,
                    filter_executed,
                    role,
                    filter_executed ? active_sboxes[role] : 255u,
                    mask,
                    value,
                    actual_words[role],
                    known_bits,
                    role_correct
                );
            }
        }

        printf("completed trial %zu/%zu\n", trial + 1u, trials);
    }

    if (fclose(trial_file) != 0 || fclose(role_file) != 0) {
        fputs("FAIL: closing output files failed.\n", stderr);
        return 1;
    }

    printf("raw trial CSV: %s\n", trial_path);
    printf("raw role CSV:  %s\n", role_path);
    printf("trials:        %zu\n", trials);
    printf("sample grid:   ");
    for (trial = 0u; trial < GRID_POINTS; ++trial) {
        printf("%zu%s", SAMPLE_GRID[trial],
               trial + 1u == GRID_POINTS ? "\n" : ",");
    }
    puts("PASS: repeated unknown-fault experiments completed.");
    return 0;
}
