#include "unknown_detection_attack.h"

#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEFAULT_CANDIDATES "results/scenario2_active_key_candidates.csv"
#define DEFAULT_SUMMARY    "results/scenario2_partial_decryption_summary.csv"
#define DEFAULT_TRUTH      "results/scenario2_unknown_detection_ground_truth.csv"

static int parse_u64_text(const char *text, uint64_t *value)
{
    char *end = NULL;
    unsigned long long parsed;

    errno = 0;
    parsed = strtoull(text, &end, 0);
    if (errno != 0 || end == text || (*end != '\0' && *end != '\r' && *end != '\n')) {
        return -1;
    }
    *value = (uint64_t)parsed;
    return 0;
}

static int read_parameter_u64(
    const char *path,
    const char *parameter,
    uint64_t *value
)
{
    FILE *file = fopen(path, "r");
    char line[256];

    if (file == NULL) {
        perror(path);
        return -1;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        char *comma = strchr(line, ',');
        if (comma == NULL) {
            continue;
        }
        *comma = '\0';
        if (strcmp(line, parameter) == 0) {
            char *text = comma + 1;
            char *newline = strpbrk(text, "\r\n");
            int status;
            if (newline != NULL) {
                *newline = '\0';
            }
            status = parse_u64_text(text, value);
            fclose(file);
            return status;
        }
    }
    fclose(file);
    fprintf(stderr, "FAIL: parameter %s missing from %s.\n", parameter, path);
    return -1;
}

static int candidate_file_contains(
    const char *path,
    uint32_t expected,
    size_t *candidate_count,
    size_t *matching_index
)
{
    FILE *file = fopen(path, "r");
    char line[512];
    size_t count = 0u;
    int found = 0;

    if (file == NULL) {
        perror(path);
        return -1;
    }
    if (fgets(line, sizeof(line), file) == NULL) {
        fclose(file);
        return -1;
    }
    while (fgets(line, sizeof(line), file) != NULL) {
        char *first = strchr(line, ',');
        char *second;
        uint64_t packed;

        if (first == NULL) {
            continue;
        }
        second = strchr(first + 1, ',');
        if (second == NULL) {
            continue;
        }
        *second = '\0';
        if (parse_u64_text(first + 1, &packed) != 0) {
            fclose(file);
            return -1;
        }
        if ((uint32_t)packed == expected) {
            found = 1;
            *matching_index = count;
        }
        ++count;
    }
    fclose(file);
    *candidate_count = count;
    return found;
}

int main(int argc, char **argv)
{
    const char *candidate_path = DEFAULT_CANDIDATES;
    const char *summary_path = DEFAULT_SUMMARY;
    const char *truth_path = DEFAULT_TRUTH;
    uint64_t actual_sk28_u64;
    uint64_t secret_delta_u64;
    uint64_t secret_sbox_u64;
    uint64_t recovered_delta_u64;
    uint64_t recovered_bits_u64;
    uint64_t survivors_u64;
    uint32_t actual_packed;
    size_t candidate_count = 0u;
    size_t matching_index = 0u;
    FILE *verification;
    int found;

    if (argc > 1) {
        candidate_path = argv[1];
    }
    if (argc > 2) {
        summary_path = argv[2];
    }
    if (argc > 3) {
        truth_path = argv[3];
    }
    if (argc > 4) {
        fprintf(stderr,
                "Usage: %s [candidate_csv] [partial_summary_csv] [ground_truth_csv]\n",
                argv[0]);
        return 2;
    }

    if (read_parameter_u64(truth_path, "actual_sk28", &actual_sk28_u64) != 0 ||
        read_parameter_u64(truth_path, "secret_delta", &secret_delta_u64) != 0 ||
        read_parameter_u64(truth_path, "secret_sbox", &secret_sbox_u64) != 0 ||
        read_parameter_u64(summary_path, "recovered_delta", &recovered_delta_u64) != 0 ||
        read_parameter_u64(summary_path, "recovered_active_bits", &recovered_bits_u64) != 0 ||
        read_parameter_u64(summary_path, "surviving_candidates", &survivors_u64) != 0) {
        return 1;
    }

    actual_packed = scenery_unknown_pack_round_key_active_words(
        (uint32_t)actual_sk28_u64,
        (uint8_t)secret_sbox_u64
    );
    found = candidate_file_contains(
        candidate_path,
        actual_packed,
        &candidate_count,
        &matching_index
    );
    if (found < 0) {
        return 1;
    }

    verification = fopen("results/scenario2_step2_verification.csv", "w");
    if (verification == NULL) {
        perror("results/scenario2_step2_verification.csv");
        return 1;
    }
    fputs("parameter,value\n", verification);
    fprintf(verification, "secret_sbox,%" PRIu64 "\n", secret_sbox_u64);
    fprintf(verification, "secret_delta,0x%" PRIX64 "\n", secret_delta_u64);
    fprintf(verification, "recovered_delta,0x%" PRIX64 "\n", recovered_delta_u64);
    fprintf(verification, "actual_sk28,0x%08" PRIX64 "\n", actual_sk28_u64);
    fprintf(verification, "actual_packed_active_key,0x%05" PRIX32 "\n",
            actual_packed);
    fprintf(verification, "candidate_count,%zu\n", candidate_count);
    fprintf(verification, "actual_candidate_present,%s\n", found ? "YES" : "NO");
    if (found) {
        fprintf(verification, "actual_candidate_index,%zu\n", matching_index);
    }
    fprintf(verification, "recovered_active_bits,%" PRIu64 "\n",
            recovered_bits_u64);
    fprintf(verification, "status,%s\n",
            found && recovered_delta_u64 == secret_delta_u64 &&
            survivors_u64 == candidate_count && recovered_bits_u64 == 18u
                ? "PASS" : "FAIL");
    fclose(verification);

    puts("Scenario 2 / Step 2 verification boundary");
    printf("secret S-box:               %" PRIu64 "\n", secret_sbox_u64);
    printf("secret delta:               0x%" PRIX64 "\n", secret_delta_u64);
    printf("recovered delta:            0x%" PRIX64 "\n", recovered_delta_u64);
    printf("actual SK28:                0x%08" PRIX64 "\n", actual_sk28_u64);
    printf("actual packed active key:   0x%05" PRIX32 "\n", actual_packed);
    printf("candidate count:            %zu\n", candidate_count);
    printf("actual candidate present:   %s\n", found ? "YES" : "NO");
    printf("recovered active key bits:  %" PRIu64 "/20\n", recovered_bits_u64);
    puts("verification: results/scenario2_step2_verification.csv");

    if (!found || recovered_delta_u64 != secret_delta_u64 ||
        survivors_u64 != candidate_count || recovered_bits_u64 != 18u) {
        fputs("FAIL: Step-2 verification did not match simulation truth.\n", stderr);
        return 1;
    }
    puts("PASS: the true active key is in the public candidate set and delta was recovered correctly.");
    return 0;
}
