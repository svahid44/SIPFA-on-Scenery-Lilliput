#include "infection_dataset.h"
#include "known_detection_attack.h"
#include "persistent_fault.h"
#include "scenery.h"
#include "unknown_detection_attack.h"
#include "unknown_infection_attack.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SAMPLE_COUNT UINT64_C(4096)
#define DATASET_SEED UINT64_C(0xBB67AE8584CAA73B)
#define SECRET_SBOX UINT8_C(5)
#define SECRET_DELTA UINT8_C(0xB)

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

typedef struct capture_context {
    uint8_t *ciphertexts;
    size_t capacity;
    size_t count;
} capture_context;

static int capture_public_output(
    uint64_t sample_index,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    void *user_data
)
{
    capture_context *capture = (capture_context *)user_data;

    (void)sample_index;
    if (capture == NULL || ciphertext == NULL ||
        capture->count >= capture->capacity) {
        return -1;
    }
    memcpy(
        capture->ciphertexts + capture->count * SCENERY_BLOCK_SIZE,
        ciphertext,
        SCENERY_BLOCK_SIZE
    );
    ++capture->count;
    return 0;
}

static int verify_role_c_truth_table(void)
{
    const uint8_t words[4] = { 0x3u, 0x7u, 0xBu, 0xFu };
    size_t input;

    for (input = 0u; input < 16u; ++input) {
        uint8_t contribution[4];
        size_t candidate;

        for (candidate = 0u; candidate < 4u; ++candidate) {
            contribution[candidate] = (uint8_t)(
                scenery_sbox_correct(
                    (uint8_t)(input ^ words[candidate])
                ) & 1u
            );
        }
        if (contribution[0] != contribution[3] ||
            contribution[1] != contribution[2] ||
            contribution[0] == contribution[1]) {
            return -1;
        }
    }
    return 0;
}

int main(void)
{
    const uint8_t key[SCENERY_KEY_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99
    };
    const uint32_t candidates[4] = {
        UINT32_C(0x3B37E),
        UINT32_C(0x3B77E),
        UINT32_C(0x3BB7E),
        UINT32_C(0x3BF7E)
    };
    const uint8_t expected_xor[4][4] = {
        { 0u, 1u, 1u, 0u },
        { 1u, 0u, 0u, 1u },
        { 1u, 0u, 0u, 1u },
        { 0u, 1u, 1u, 0u }
    };
    const uint8_t faulty_output = (uint8_t)(
        (scenery_sbox_correct(SECRET_DELTA) + 1u) & 0x0Fu
    );
    scenery_ctx ctx;
    scenery_infection_stats stats;
    capture_context capture;
    scenery_unknown_infection_equivalence_result audit;
    uint32_t actual_packed;
    size_t first;
    int status;

    memset(&capture, 0, sizeof(capture));
    capture.capacity = (size_t)SAMPLE_COUNT;
    capture.ciphertexts = (uint8_t *)malloc(
        capture.capacity * SCENERY_BLOCK_SIZE
    );
    if (capture.ciphertexts == NULL) {
        return fail("ciphertext allocation failed");
    }
    if (scenery_init(&ctx, key) != 0) {
        free(capture.ciphertexts);
        return fail("scenery_init failed");
    }

    scenery_fault_reset();
    if (scenery_fault_inject(
            SECRET_SBOX,
            SECRET_DELTA,
            faulty_output) != 0) {
        free(capture.ciphertexts);
        return fail("fault injection failed");
    }
    status = scenery_infection_collect(
        &ctx,
        SAMPLE_COUNT,
        DATASET_SEED,
        &stats,
        capture_public_output,
        &capture
    );
    scenery_fault_reset();
    if (status != 0 || capture.count != (size_t)SAMPLE_COUNT) {
        free(capture.ciphertexts);
        return fail("infection dataset collection failed");
    }

    status = scenery_unknown_infection_audit_candidate_equivalence(
        capture.ciphertexts,
        capture.count,
        SECRET_SBOX,
        candidates,
        4u,
        &audit
    );
    if (status != 0 || !audit.success) {
        free(capture.ciphertexts);
        return fail("equivalence audit failed");
    }
    if (audit.unique_exact_sequences != 2u ||
        audit.xor_equivalence_classes != 1u ||
        audit.unique_score_count != 1u ||
        !audit.all_pairs_xor_equivalent) {
        free(capture.ciphertexts);
        return fail("rank-1 class is not the expected structural equivalence");
    }

    for (first = 0u; first < 4u; ++first) {
        size_t second;

        if (audit.score_numerators[first] != audit.score_numerators[0]) {
            free(capture.ciphertexts);
            return fail("SEI numerators differ inside the equivalence class");
        }
        for (second = 0u; second < 4u; ++second) {
            if (!audit.constant_xor_valid[first][second] ||
                audit.constant_xor[first][second] != expected_xor[first][second] ||
                !audit.histogram_permutation_equal[first][second]) {
                free(capture.ciphertexts);
                return fail("pairwise constant-XOR relation differs");
            }
        }
    }
    if (verify_role_c_truth_table() != 0) {
        free(capture.ciphertexts);
        return fail("role-C S-box truth-table proof failed");
    }

    actual_packed = scenery_unknown_pack_round_key_active_words(
        ctx.round_keys[SCENERY_ROUNDS - 1u],
        SECRET_SBOX
    );
    if (actual_packed != UINT32_C(0x3BB7E)) {
        free(capture.ciphertexts);
        return fail("verification active key differs from reference");
    }

    puts("Scenario 4 / Step 3 unit test: structural-equivalence proof");
    printf("public samples:              %zu\n", capture.count);
    printf("rank-1 candidates:           %zu\n", audit.candidate_count);
    printf("unique exact sequences:      %zu\n", audit.unique_exact_sequences);
    printf("XOR-equivalence classes:     %zu\n", audit.xor_equivalence_classes);
    printf("unique SEI scores:           %zu\n", audit.unique_score_count);
    printf("common score numerator:      %" PRIu64 "\n",
           audit.score_numerators[0]);
    printf("actual active candidate:     0x%05" PRIX32 "\n", actual_packed);
    puts("PASS: the two unresolved bits are structurally unidentifiable under the current one-word SEI observation; the honest result remains 18/20 bits plus the unique delta.");

    free(capture.ciphertexts);
    return 0;
}
