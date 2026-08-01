#include "detection_dataset.h"
#include "known_detection_attack.h"
#include "persistent_fault.h"
#include "scenery.h"
#include "unknown_detection_attack.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TARGET_INEFFECTIVE UINT64_C(256)
#define MAX_QUERIES        UINT64_C(10000)
#define TEST_SEED          UINT64_C(0x243F6A8885A308D3)

struct capture_context {
    uint8_t ciphertexts[TARGET_INEFFECTIVE][SCENERY_BLOCK_SIZE];
    size_t count;
};

static int capture_ciphertext(
    uint64_t query_index,
    uint64_t ineffective_index,
    const uint8_t plaintext[SCENERY_BLOCK_SIZE],
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    void *user_data
)
{
    struct capture_context *capture = (struct capture_context *)user_data;

    (void)query_index;
    (void)ineffective_index;
    (void)plaintext;

    if (capture == NULL || capture->count >= TARGET_INEFFECTIVE) {
        return -1;
    }
    memcpy(
        capture->ciphertexts[capture->count],
        ciphertext,
        SCENERY_BLOCK_SIZE
    );
    ++capture->count;
    return 0;
}

int main(void)
{
    const uint8_t key[SCENERY_KEY_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99
    };
    const uint8_t secret_sbox = 5u;
    const uint8_t secret_delta = 0xBu;
    const uint8_t correct_output = scenery_sbox_correct(secret_delta);
    const uint8_t faulty_output =
        (uint8_t)((correct_output + 1u) & 0x0Fu);
    scenery_ctx ctx;
    scenery_detection_stats stats;
    scenery_unknown_detection_result attack;
    struct capture_context capture;
    uint8_t actual_word;
    uint8_t expected_missing;
    size_t sample;
    size_t sbox;
    int status;

    memset(&capture, 0, sizeof(capture));
    if (scenery_init(&ctx, key) != 0) {
        fputs("FAIL: scenery_init failed.\n", stderr);
        return 1;
    }

    scenery_fault_reset();
    if (scenery_fault_inject(
            secret_sbox,
            secret_delta,
            faulty_output) != 0) {
        fputs("FAIL: fault injection failed.\n", stderr);
        return 1;
    }

    status = scenery_detection_collect(
        &ctx,
        TARGET_INEFFECTIVE,
        MAX_QUERIES,
        TEST_SEED,
        &stats,
        capture_ciphertext,
        &capture
    );
    scenery_fault_reset();
    if (status != 0 || capture.count != TARGET_INEFFECTIVE) {
        fprintf(stderr,
                "FAIL: collection status=%d count=%zu.\n",
                status,
                capture.count);
        return 1;
    }

    scenery_unknown_detection_result_init(&attack);
    for (sample = 0u; sample < capture.count; ++sample) {
        if (scenery_unknown_detection_add_ciphertext(
                &attack,
                capture.ciphertexts[sample]) != 0) {
            fputs("FAIL: attack ingestion failed.\n", stderr);
            return 1;
        }
    }

    status = scenery_unknown_detection_identify_fault(&attack);
    actual_word = scenery_round_key_sbox_word(
        ctx.round_keys[SCENERY_ROUNDS - 1u],
        secret_sbox
    );
    expected_missing = (uint8_t)(secret_delta ^ actual_word);

    puts("Scenario 2 / Step 1 unit test: unknown fault localization");
    printf("public ineffective samples: %zu\n", capture.count);
    printf("total oracle queries:       %" PRIu64 "\n", stats.total_queries);
    puts("sbox  missing_count");
    for (sbox = 0u; sbox < SCENERY_UNKNOWN_DETECTION_SBOXES; ++sbox) {
        printf("%4zu  %zu\n", sbox, attack.missing_count_per_sbox[sbox]);
    }
    printf("global missing count:       %zu\n", attack.total_missing_count);
    printf("detected S-box:             %u\n", attack.detected_sbox);
    printf("actual S-box:               %u\n", secret_sbox);
    printf("detected missing value:     0x%X\n",
           attack.detected_missing_value);
    printf("expected delta XOR SK28:    0x%X\n", expected_missing);
    printf("secret delta (verification): 0x%X\n", secret_delta);
    printf("actual SK28 word:           0x%X\n", actual_word);

    if (status != 0 || !attack.success ||
        attack.total_missing_count != 1u ||
        attack.detected_sbox != secret_sbox ||
        attack.detected_missing_value != expected_missing) {
        fputs("FAIL: Algorithm-2 fault localization was incorrect.\n", stderr);
        return 1;
    }

    puts("PASS: one global missing value identified the unknown faulty S-box and public missing word.");
    return 0;
}
