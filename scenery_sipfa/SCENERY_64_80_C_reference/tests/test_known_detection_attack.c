#include "detection_dataset.h"
#include "known_detection_attack.h"
#include "persistent_fault.h"
#include "scenery.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#define TARGET_INEFFECTIVE UINT64_C(4096)
#define MAX_QUERIES        UINT64_C(50000)
#define DATASET_SEED       UINT64_C(0xBB67AE8584CAA73B)

static int collect_for_attack(
    uint64_t query_index,
    uint64_t ineffective_index,
    const uint8_t plaintext[SCENERY_BLOCK_SIZE],
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    void *user_data
)
{
    scenery_known_detection_result *result =
        (scenery_known_detection_result *)user_data;

    (void)query_index;
    (void)ineffective_index;
    (void)plaintext;
    return scenery_known_detection_add_ciphertext(result, ciphertext);
}

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

int main(void)
{
    const uint8_t key[SCENERY_KEY_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99
    };
    const uint8_t target_sbox = 3u;
    const uint8_t delta = 0x5u;
    const uint8_t correct_output = scenery_sbox_correct(delta);
    const uint8_t faulty_output =
        (uint8_t)((correct_output + 1u) & 0x0Fu);
    scenery_ctx ctx;
    scenery_detection_stats stats;
    scenery_known_detection_result result;
    uint64_t histogram_total = 0u;
    uint8_t actual_word;
    uint8_t expected_missing;
    size_t value;
    int status;

    if (scenery_init(&ctx, key) != 0) {
        return fail("scenery_init failed");
    }

    scenery_fault_reset();
    if (scenery_fault_inject(target_sbox, delta, faulty_output) != 0) {
        return fail("persistent fault injection failed");
    }

    scenery_known_detection_result_init(&result, target_sbox, delta);
    status = scenery_detection_collect(
        &ctx,
        TARGET_INEFFECTIVE,
        MAX_QUERIES,
        DATASET_SEED,
        &stats,
        collect_for_attack,
        &result
    );
    if (status != 0) {
        return fail("ineffective dataset collection failed");
    }

    if (result.sample_count != TARGET_INEFFECTIVE) {
        return fail("attack histogram did not receive every released sample");
    }
    for (value = 0u; value < SCENERY_ATTACK_DOMAIN; ++value) {
        histogram_total += result.histogram[value];
    }
    if (histogram_total != TARGET_INEFFECTIVE) {
        return fail("histogram total is inconsistent");
    }

    status = scenery_known_detection_recover_word(&result);
    if (status != 0 || !result.success) {
        return fail("known-fault word recovery did not produce a unique value");
    }

    actual_word = scenery_round_key_sbox_word(
        ctx.round_keys[SCENERY_ROUNDS - 1u],
        target_sbox
    );
    expected_missing = (uint8_t)(delta ^ actual_word);

    if (result.missing_count != 1u) {
        return fail("histogram does not contain exactly one missing value");
    }
    if (result.missing_values[0] != expected_missing) {
        return fail("missing value does not equal delta XOR SK28 word");
    }
    if (result.recovered_round_key_word != actual_word) {
        return fail("recovered SK28 word differs from ground truth");
    }

    printf("target logical S-box:  %u\n", target_sbox);
    printf("known delta:           0x%X\n", delta);
    printf("ineffective samples:   %" PRIu64 "\n", result.sample_count);
    puts("value  count");
    for (value = 0u; value < SCENERY_ATTACK_DOMAIN; ++value) {
        printf("0x%zX   %" PRIu64 "%s\n",
               value,
               result.histogram[value],
               result.histogram[value] == 0u ? "  <-- unique missing" : "");
    }
    printf("missing value:         0x%X\n", result.missing_values[0]);
    printf("recovered SK28 word:   0x%X\n", result.recovered_round_key_word);
    printf("actual SK28:           %08" PRIX32 "\n",
           ctx.round_keys[SCENERY_ROUNDS - 1u]);
    printf("actual SK28 word:      0x%X\n", actual_word);

    scenery_fault_reset();
    puts("PASS: Algorithm-1 missing-value recovery reproduced the target four bits of SK28.");
    return 0;
}
