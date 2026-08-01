#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "infection_dataset.h"
#include "known_detection_attack.h"
#include "persistent_fault.h"
#include "scenery.h"
#include "unknown_infection_attack.h"

#define SAMPLE_COUNT UINT64_C(32768)
#define DATASET_SEED UINT64_C(0x6A09E667F3BCC909)
#define SECRET_SBOX UINT8_C(5)
#define SECRET_DELTA UINT8_C(0xB)

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

static int add_public_output(
    uint64_t sample_index,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    void *user_data
)
{
    scenery_unknown_infection_result *result =
        (scenery_unknown_infection_result *)user_data;

    (void)sample_index;
    return scenery_unknown_infection_add_ciphertext(result, ciphertext);
}

int main(void)
{
    const uint8_t key[SCENERY_KEY_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99
    };
    const uint8_t faulty_output = (uint8_t)(
        (scenery_sbox_correct(SECRET_DELTA) + 1u) & 0x0Fu
    );
    scenery_ctx ctx;
    scenery_infection_stats stats;
    scenery_unknown_infection_result result;
    uint8_t actual_word;
    uint8_t expected_minimum;
    size_t sbox;
    int status;

    if (scenery_init(&ctx, key) != 0) {
        return fail("scenery_init failed");
    }

    scenery_fault_reset();
    if (scenery_fault_inject(
            SECRET_SBOX,
            SECRET_DELTA,
            faulty_output) != 0) {
        return fail("persistent fault injection failed");
    }

    scenery_unknown_infection_result_init(&result);
    status = scenery_infection_collect(
        &ctx,
        SAMPLE_COUNT,
        DATASET_SEED,
        &stats,
        add_public_output,
        &result
    );
    if (status != 0) {
        return fail("infection dataset collection failed");
    }
    if (stats.published_count != SAMPLE_COUNT ||
        stats.published_count !=
            stats.internal_ineffective_count + stats.internal_effective_count) {
        return fail("infection statistics are inconsistent");
    }
    if (result.sample_count != SAMPLE_COUNT) {
        return fail("attack did not receive every public ciphertext");
    }

    for (sbox = 0u; sbox < SCENERY_UNKNOWN_INFECTION_SBOXES; ++sbox) {
        uint64_t total = 0u;
        size_t value;
        for (value = 0u;
             value < SCENERY_UNKNOWN_INFECTION_DOMAIN;
             ++value) {
            total += result.histogram[sbox][value];
        }
        if (total != SAMPLE_COUNT) {
            return fail("one public histogram has the wrong total");
        }
    }

    status = scenery_unknown_infection_identify_fault(&result);
    if (status != 0 || !result.success) {
        return fail("Algorithm-4 SEI localization was not unique");
    }
    if (result.detected_sbox != SECRET_SBOX) {
        return fail("SEI maximum does not identify the faulty logical S-box");
    }
    if (result.lane_rank[SECRET_SBOX] != 1u || result.sei_gap <= 0.0) {
        return fail("faulty lane has no positive unique SEI separation");
    }
    if (result.minimum_multiplicity[SECRET_SBOX] != 1u) {
        return fail("faulty-lane minimum is not unique");
    }

    actual_word = scenery_round_key_sbox_word(
        ctx.round_keys[SCENERY_ROUNDS - 1u],
        SECRET_SBOX
    );
    expected_minimum = (uint8_t)(SECRET_DELTA ^ actual_word);
    if (result.detected_public_minimum != expected_minimum) {
        return fail("public minimum is not delta XOR the actual SK28 word");
    }
    if (scenery_unknown_infection_key_word_candidate(
            result.detected_public_minimum,
            SECRET_DELTA) != actual_word) {
        return fail("the actual delta does not map to the actual SK28 word");
    }

    printf("secret logical S-box:       %u\n", SECRET_SBOX);
    printf("secret delta:               0x%X\n", SECRET_DELTA);
    printf("published samples:          %" PRIu64 "\n", stats.published_count);
    printf("internal ineffective:       %" PRIu64 "\n",
           stats.internal_ineffective_count);
    printf("internal infected:          %" PRIu64 "\n",
           stats.internal_effective_count);
    printf("detected logical S-box:     %u\n", result.detected_sbox);
    printf("detected public minimum:    0x%X\n",
           result.detected_public_minimum);
    printf("best SEI:                   %.12g\n", result.best_sei);
    printf("second-best SEI:            %.12g\n", result.second_best_sei);
    printf("SEI gap:                    %.12g\n", result.sei_gap);
    printf("actual SK28 word:           0x%X\n", actual_word);
    printf("coupled hypotheses:         %u\n",
           (unsigned int)SCENERY_UNKNOWN_INFECTION_CANDIDATES);

    scenery_fault_reset();
    puts("PASS: Algorithm-4 Step 1 localized the unknown infected fault and retained the true delta/key-word pair among 16 coupled candidates.");
    return 0;
}
