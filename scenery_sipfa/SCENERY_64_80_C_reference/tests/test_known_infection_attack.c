#include "detection_dataset.h"
#include "infection_dataset.h"
#include "known_detection_attack.h"
#include "known_infection_attack.h"
#include "persistent_fault.h"
#include "scenery.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#define SAMPLE_COUNT UINT64_C(32768)
#define DATASET_SEED UINT64_C(0xA4093822299F31D0)

static int add_public_output(
    uint64_t sample_index,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    void *user_data
)
{
    scenery_known_infection_result *result =
        (scenery_known_infection_result *)user_data;

    (void)sample_index;
    return scenery_known_infection_add_ciphertext(result, ciphertext);
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
    const uint8_t faulty_output = (uint8_t)(
        (scenery_sbox_correct(delta) + 1u) & 0x0Fu
    );
    scenery_ctx ctx;
    scenery_infection_stats stats;
    scenery_known_infection_result result;
    uint64_t histogram_total = 0u;
    uint8_t actual_word;
    uint8_t expected_minimum;
    size_t value;
    int status;

    if (scenery_init(&ctx, key) != 0) {
        return fail("scenery_init failed");
    }

    scenery_fault_reset();
    if (scenery_fault_inject(target_sbox, delta, faulty_output) != 0) {
        return fail("persistent fault injection failed");
    }

    scenery_known_infection_result_init(&result, target_sbox, delta);
    status = scenery_infection_collect(
        &ctx,
        SAMPLE_COUNT,
        DATASET_SEED,
        &stats,
        add_public_output,
        &result
    );
    if (status != 0) {
        return fail("infection-based public dataset collection failed");
    }

    if (stats.published_count != SAMPLE_COUNT ||
        stats.published_count !=
            stats.internal_ineffective_count + stats.internal_effective_count) {
        return fail("infection statistics are inconsistent");
    }
    if (result.sample_count != SAMPLE_COUNT) {
        return fail("attack did not receive every public ciphertext");
    }

    for (value = 0u; value < SCENERY_ATTACK_DOMAIN; ++value) {
        histogram_total += result.histogram[value];
    }
    if (histogram_total != SAMPLE_COUNT) {
        return fail("histogram total is inconsistent");
    }

    status = scenery_known_infection_recover_word(&result);
    if (status != 0 || !result.success) {
        return fail("minimum-frequency recovery did not produce a unique value");
    }

    actual_word = scenery_round_key_sbox_word(
        ctx.round_keys[SCENERY_ROUNDS - 1u],
        target_sbox
    );
    expected_minimum = (uint8_t)(delta ^ actual_word);

    if (result.minimum_value != expected_minimum) {
        return fail("minimum does not equal delta XOR the actual SK28 word");
    }
    if (result.recovered_round_key_word != actual_word) {
        return fail("recovered SK28 word differs from ground truth");
    }
    if (result.minimum_multiplicity != 1u ||
        result.second_minimum_count <= result.minimum_count) {
        return fail("minimum-frequency separation is not positive and unique");
    }

    printf("target logical S-box:      %u\n", target_sbox);
    printf("known delta:               0x%X\n", delta);
    printf("published samples:         %" PRIu64 "\n", stats.published_count);
    printf("internal ineffective:      %" PRIu64 "\n",
           stats.internal_ineffective_count);
    printf("internal infected:         %" PRIu64 "\n",
           stats.internal_effective_count);
    printf("empirical ineffective rate: %.9f\n",
           (double)stats.internal_ineffective_count /
           (double)stats.published_count);
    printf("theoretical ineffective rate: %.9f\n",
           scenery_detection_theoretical_ineffective_rate());
    puts("value  count");
    for (value = 0u; value < SCENERY_ATTACK_DOMAIN; ++value) {
        printf("0x%zX   %" PRIu64 "%s\n",
               value,
               result.histogram[value],
               value == (size_t)result.minimum_value
                   ? "  <-- unique minimum"
                   : "");
    }
    printf("minimum value:             0x%X\n", result.minimum_value);
    printf("minimum count:             %" PRIu64 "\n", result.minimum_count);
    printf("second minimum count:      %" PRIu64 "\n",
           result.second_minimum_count);
    printf("minimum gap:               %" PRIu64 "\n",
           result.second_minimum_count - result.minimum_count);
    printf("recovered SK28 word:       0x%X\n",
           result.recovered_round_key_word);
    printf("actual SK28 word:          0x%X\n", actual_word);

    scenery_fault_reset();
    puts("PASS: Algorithm-3 minimum-frequency recovery reproduced the target four bits of SK28.");
    return 0;
}
