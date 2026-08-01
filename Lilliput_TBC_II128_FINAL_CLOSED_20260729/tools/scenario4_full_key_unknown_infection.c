#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cipher.h"
#include "constants.h"
#include "infection_dataset.h"
#include "persistent_fault.h"
#include "reference_validation.h"
#include "unknown_infection_full_recovery.h"

#define DEFAULT_SAMPLES UINT64_C(100000)
#define DEFAULT_SECRET_DELTA UINT8_C(0x5a)
#define DEFAULT_FAULT_XOR UINT8_C(0x01)
#define DEFAULT_SEED UINT64_C(0x9B05688C2B3E6C1F)

typedef struct capture_context {
    FILE *file;
    uint8_t *ciphertexts;
    size_t capacity;
} capture_context;

static void print_hex(FILE *stream, const uint8_t *data, size_t length)
{
    for (size_t index = 0U; index < length; ++index) {
        fprintf(stream, "%02x", data[index]);
    }
}

static int parse_u64(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    errno = 0;
    parsed = strtoull(text, &end, 0);
    if ((errno != 0) || (end == text) || (*end != '\0')) {
        return -1;
    }
    *value = (uint64_t)parsed;
    return 0;
}

static int parse_u8(const char *text, uint8_t *value)
{
    uint64_t parsed;

    if ((parse_u64(text, &parsed) != 0) || (parsed > UINT8_MAX)) {
        return -1;
    }
    *value = (uint8_t)parsed;
    return 0;
}

static int capture_published(
    uint64_t sample_index,
    const uint8_t ciphertext[BLOCK_BYTES],
    void *user_data
)
{
    capture_context *context = user_data;
    size_t index;

    if ((context == NULL) || (context->file == NULL) ||
        (context->ciphertexts == NULL) || (sample_index == 0U) ||
        (sample_index > (uint64_t)context->capacity)) {
        return -1;
    }

    index = (size_t)(sample_index - 1U);
    memcpy(context->ciphertexts + index * BLOCK_BYTES,
           ciphertext,
           BLOCK_BYTES);

    fprintf(context->file, "%" PRIu64 ",", sample_index);
    print_hex(context->file, ciphertext, BLOCK_BYTES);
    fputc('\n', context->file);
    return ferror(context->file) ? -1 : 0;
}

static int write_candidates_csv(
    const char *path,
    const lilliput_unknown_infection_result *stage1
)
{
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        return -1;
    }

    fputs("delta_candidate,aggregate_sei,rank,is_recovered", file);
    for (size_t lane = 0U; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
        fprintf(file, ",lane%zu_sei", lane);
    }
    fputc('\n', file);

    for (size_t delta = 0U;
         delta < LILLIPUT_UNKNOWN_INFECTION_CANDIDATES;
         ++delta) {
        fprintf(file,
                "%zu,%.12e,%zu,%u",
                delta,
                stage1->candidate_sei[delta],
                stage1->candidate_rank[delta],
                stage1->recovered_delta == (uint8_t)delta ? 1U : 0U);
        for (size_t lane = 0U; lane < LILLIPUT_LAST_ROUND_LANES; ++lane) {
            fprintf(file, ",%.12e", stage1->candidate_lane_sei[delta][lane]);
        }
        fputc('\n', file);
    }

    if (fclose(file) != 0) {
        perror(path);
        return -1;
    }
    return 0;
}

static int write_summary(
    const char *path,
    const lilliput_unknown_infection_full_result *result,
    const lilliput_infection_stats *stats,
    uint8_t actual_delta,
    const uint8_t actual_rtk30[ROUND_TWEAKEY_BYTES],
    const uint8_t actual_rtk31[ROUND_TWEAKEY_BYTES],
    const uint8_t actual_key[KEY_BYTES],
    const uint8_t expected_ciphertext[BLOCK_BYTES],
    const uint8_t recovered_ciphertext[BLOCK_BYTES]
)
{
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        return -1;
    }

    fputs("category,index,observed,expected,status\n", file);
    fprintf(file,
            "DATASET,published,%" PRIu64 ",%" PRIu64 ",PASS\n",
            stats->published_count,
            stats->published_count);
    fprintf(file,
            "DELTA,recovered,0x%02x,0x%02x,%s\n",
            result->stage1.recovered_delta,
            actual_delta,
            result->stage1.recovered_delta == actual_delta ? "PASS" : "FAIL");
    fprintf(file,
            "SEI,gap,%.12e,positive,%s\n",
            result->stage1.best_score - result->stage1.second_best_score,
            result->stage1.best_score > result->stage1.second_best_score
                ? "PASS" : "FAIL");

    for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
        fprintf(file,
                "RTK31,%zu,0x%02x,0x%02x,%s\n",
                lane,
                result->stage1.recovered_round_tweakey[lane],
                actual_rtk31[lane],
                result->stage1.recovered_round_tweakey[lane] ==
                        actual_rtk31[lane]
                    ? "PASS" : "FAIL");
    }
    for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
        fprintf(file,
                "RTK30,%zu,0x%02x,0x%02x,%s\n",
                lane,
                result->recovered_rtk30[lane],
                actual_rtk30[lane],
                result->recovered_rtk30[lane] == actual_rtk30[lane]
                    ? "PASS" : "FAIL");
    }

    fprintf(file,
            "GF2,rank,%zu,128,%s\n",
            result->master_key.rank,
            result->master_key.rank == 128U ? "PASS" : "FAIL");
    fputs("MASTER_KEY,recovered,", file);
    print_hex(file, result->master_key.recovered_key, KEY_BYTES);
    fputc(',', file);
    print_hex(file, actual_key, KEY_BYTES);
    fprintf(file,
            ",%s\n",
            memcmp(result->master_key.recovered_key,
                   actual_key,
                   KEY_BYTES) == 0
                ? "PASS" : "FAIL");
    fputs("ENCRYPTION,validation,", file);
    print_hex(file, recovered_ciphertext, BLOCK_BYTES);
    fputc(',', file);
    print_hex(file, expected_ciphertext, BLOCK_BYTES);
    fprintf(file,
            ",%s\n",
            memcmp(recovered_ciphertext,
                   expected_ciphertext,
                   BLOCK_BYTES) == 0
                ? "PASS" : "FAIL");

    if (fclose(file) != 0) {
        perror(path);
        return -1;
    }
    return 0;
}

static void usage(const char *program)
{
    fprintf(stderr,
            "Usage: %s [published_samples] [secret_delta] [fault_xor] "
            "[seed] [samples.csv] [candidates.csv] [summary.csv]\n",
            program);
}

int main(int argc, char **argv)
{
    static const uint8_t validation_plaintext[BLOCK_BYTES] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    uint64_t sample_count = DEFAULT_SAMPLES;
    uint64_t seed = DEFAULT_SEED;
    uint8_t secret_delta = DEFAULT_SECRET_DELTA;
    uint8_t fault_xor = DEFAULT_FAULT_XOR;
    const char *samples_path =
        "results/scenario4_full_key_published_ciphertexts.csv";
    const char *candidates_path =
        "results/scenario4_full_key_candidates.csv";
    const char *summary_path =
        "results/scenario4_full_key_summary.csv";
    uint8_t key[KEY_BYTES];
    uint8_t tweak[TWEAK_BYTES];
    uint8_t actual_rtk30[ROUND_TWEAKEY_BYTES];
    uint8_t actual_rtk31[ROUND_TWEAKEY_BYTES];
    uint8_t expected_ciphertext[BLOCK_BYTES];
    uint8_t recovered_ciphertext[BLOCK_BYTES];
    uint8_t *published_ciphertexts = NULL;
    capture_context capture;
    lilliput_infection_stats stats;
    lilliput_unknown_infection_full_result result;
    int status;
    int success = 1;

    if ((argc > 1) && (parse_u64(argv[1], &sample_count) != 0)) {
        usage(argv[0]);
        return 2;
    }
    if ((argc > 2) && (parse_u8(argv[2], &secret_delta) != 0)) {
        usage(argv[0]);
        return 2;
    }
    if ((argc > 3) && (parse_u8(argv[3], &fault_xor) != 0)) {
        usage(argv[0]);
        return 2;
    }
    if ((argc > 4) && (parse_u64(argv[4], &seed) != 0)) {
        usage(argv[0]);
        return 2;
    }
    if (argc > 5) {
        samples_path = argv[5];
    }
    if (argc > 6) {
        candidates_path = argv[6];
    }
    if (argc > 7) {
        summary_path = argv[7];
    }
    if ((argc > 8) || (sample_count == 0U) || (fault_xor == 0U) ||
        (sample_count > (uint64_t)(SIZE_MAX / BLOCK_BYTES))) {
        usage(argv[0]);
        return 2;
    }

    for (size_t index = 0U; index < KEY_BYTES; ++index) {
        key[index] = (uint8_t)index;
        tweak[index] = (uint8_t)index;
    }

    published_ciphertexts = malloc((size_t)sample_count * BLOCK_BYTES);
    if (published_ciphertexts == NULL) {
        fputs("could not allocate public infection dataset\n", stderr);
        return 1;
    }

    capture.file = fopen(samples_path, "w");
    if (capture.file == NULL) {
        perror(samples_path);
        free(published_ciphertexts);
        return 1;
    }
    capture.ciphertexts = published_ciphertexts;
    capture.capacity = (size_t)sample_count;
    fputs("sample_index,ciphertext\n", capture.file);

    lilliput_fault_reset();
    status = lilliput_fault_inject(
        secret_delta,
        (uint8_t)(lilliput_sbox_correct(secret_delta) ^ fault_xor)
    );
    if (status != 0) {
        fclose(capture.file);
        free(published_ciphertexts);
        fputs("persistent fault injection failed\n", stderr);
        return 1;
    }

    status = lilliput_infection_collect(
        key,
        tweak,
        sample_count,
        seed,
        &stats,
        capture_published,
        &capture
    );
    if (fclose(capture.file) != 0) {
        perror(samples_path);
        lilliput_fault_reset();
        free(published_ciphertexts);
        return 1;
    }
    if (status != 0) {
        fprintf(stderr,
                "infection dataset collection failed with status %d\n",
                status);
        lilliput_fault_reset();
        free(published_ciphertexts);
        return 1;
    }

    /*
     * Attack boundary: only unlabeled public ciphertexts, their count, and
     * the public tweak enter the complete Scenario-4 recovery routine.
     */
    status = lilliput_unknown_infection_recover_full_key(
        published_ciphertexts,
        (size_t)sample_count,
        tweak,
        &result
    );
    if (status != 0) {
        fprintf(stderr,
                "FAIL: full Scenario-4 recovery returned %d\n",
                status);
        lilliput_fault_reset();
        free(published_ciphertexts);
        return 1;
    }

    if ((lilliput_reference_round_tweakey(
             key, tweak, ROUNDS - 2U, actual_rtk30) != 0) ||
        (lilliput_reference_round_tweakey(
             key, tweak, ROUNDS - 1U, actual_rtk31) != 0)) {
        lilliput_fault_reset();
        free(published_ciphertexts);
        fputs("validation RTK derivation failed\n", stderr);
        return 1;
    }

    lilliput_tbc_encrypt(
        key,
        tweak,
        validation_plaintext,
        expected_ciphertext
    );
    lilliput_tbc_encrypt(
        result.master_key.recovered_key,
        tweak,
        validation_plaintext,
        recovered_ciphertext
    );

    if ((result.stage1.recovered_delta != secret_delta) ||
        (memcmp(result.stage1.recovered_round_tweakey,
                actual_rtk31,
                ROUND_TWEAKEY_BYTES) != 0) ||
        (memcmp(result.recovered_rtk30,
                actual_rtk30,
                ROUND_TWEAKEY_BYTES) != 0) ||
        (memcmp(result.master_key.recovered_key, key, KEY_BYTES) != 0) ||
        (memcmp(expected_ciphertext,
                recovered_ciphertext,
                BLOCK_BYTES) != 0)) {
        success = 0;
    }

    if ((write_candidates_csv(candidates_path, &result.stage1) != 0) ||
        (write_summary(summary_path,
                       &result,
                       &stats,
                       secret_delta,
                       actual_rtk30,
                       actual_rtk31,
                       key,
                       expected_ciphertext,
                       recovered_ciphertext) != 0)) {
        lilliput_fault_reset();
        free(published_ciphertexts);
        return 1;
    }

    puts("Scenario 4 complete chain: unknown fault + infection-based SIPFA");
    printf("published samples:      %" PRIu64 "\n", stats.published_count);
    printf("internal ineffective:   %" PRIu64 "\n",
           stats.internal_ineffective_count);
    printf("internal effective:     %" PRIu64 "\n",
           stats.internal_effective_count);
    printf("ineffective rate:        %.6f\n",
           (double)stats.internal_ineffective_count /
               (double)stats.published_count);
    printf("recovered fault input:  0x%02x\n",
           result.stage1.recovered_delta);
    printf("actual fault input:     0x%02x\n", secret_delta);
    printf("best aggregate SEI:     %.12e\n", result.stage1.best_score);
    printf("second aggregate SEI:   %.12e\n",
           result.stage1.second_best_score);
    printf("SEI gap:                %.12e\n",
           result.stage1.best_score - result.stage1.second_best_score);
    fputs("recovered RTK[31]:      ", stdout);
    print_hex(stdout,
              result.stage1.recovered_round_tweakey,
              ROUND_TWEAKEY_BYTES);
    fputc('\n', stdout);
    fputs("actual RTK[31]:         ", stdout);
    print_hex(stdout, actual_rtk31, ROUND_TWEAKEY_BYTES);
    fputc('\n', stdout);
    fputs("recovered RTK[30]:      ", stdout);
    print_hex(stdout, result.recovered_rtk30, ROUND_TWEAKEY_BYTES);
    fputc('\n', stdout);
    fputs("actual RTK[30]:         ", stdout);
    print_hex(stdout, actual_rtk30, ROUND_TWEAKEY_BYTES);
    fputc('\n', stdout);
    printf("GF(2) rank:             %zu\n", result.master_key.rank);
    printf("unique solution:        %s\n",
           result.master_key.unique != 0 ? "yes" : "no");
    fputs("recovered master key:   ", stdout);
    print_hex(stdout, result.master_key.recovered_key, KEY_BYTES);
    fputc('\n', stdout);
    fputs("actual master key:      ", stdout);
    print_hex(stdout, key, KEY_BYTES);
    fputc('\n', stdout);
    fputs("validation ciphertext:  ", stdout);
    print_hex(stdout, recovered_ciphertext, BLOCK_BYTES);
    fputc('\n', stdout);
    printf("samples CSV:            %s\n", samples_path);
    printf("candidates CSV:         %s\n", candidates_path);
    printf("summary CSV:            %s\n", summary_path);

    lilliput_fault_reset();
    free(published_ciphertexts);

    if (!success) {
        fputs("FAIL: Scenario-4 full-key validation mismatch\n", stderr);
        return 1;
    }

    puts("PASS: Scenario 4 recovered the unknown fault input, RTK[31], RTK[30], and the full 128-bit master key from unlabeled infection-based ciphertexts.");
    return 0;
}
