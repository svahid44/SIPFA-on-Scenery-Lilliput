#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "infection_dataset.h"
#include "known_detection_attack.h"
#include "persistent_fault.h"
#include "scenery.h"
#include "unknown_detection_attack.h"
#include "unknown_infection_attack.h"

#define SAMPLE_COUNT UINT64_C(65536)
#define DATASET_SEED UINT64_C(0x6A09E667F3BCC909)
#define SECRET_SBOX UINT8_C(5)
#define SECRET_DELTA UINT8_C(0xB)
#define TOP_CAPACITY 16u

typedef struct capture_context {
    uint8_t *ciphertexts;
    size_t capacity;
    size_t count;
    scenery_unknown_infection_result localization;
} capture_context;

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

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
    return scenery_unknown_infection_add_ciphertext(
        &capture->localization,
        ciphertext
    );
}

static uint64_t direct_score_numerator(
    const uint8_t *ciphertexts,
    size_t sample_count,
    uint8_t target_sbox,
    uint32_t packed_words
)
{
    uint64_t histogram[16] = { 0u };
    uint64_t sum_squares = 0u;
    size_t sample;
    size_t value;

    for (sample = 0u; sample < sample_count; ++sample) {
        const uint8_t previous_word =
            scenery_unknown_partial_decrypt_previous_word(
                ciphertexts + sample * SCENERY_BLOCK_SIZE,
                target_sbox,
                packed_words
            );
        ++histogram[previous_word];
    }
    for (value = 0u; value < 16u; ++value) {
        sum_squares += histogram[value] * histogram[value];
    }
    return UINT64_C(16) * sum_squares -
           (uint64_t)sample_count * (uint64_t)sample_count;
}

static int candidate_is_present(
    const scenery_unknown_infection_active_candidate *candidates,
    size_t candidate_count,
    uint32_t packed_words
)
{
    size_t index;

    for (index = 0u; index < candidate_count; ++index) {
        if (candidates[index].packed_words == packed_words) {
            return 1;
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
    const uint32_t expected_top[4] = {
        UINT32_C(0x3B37E),
        UINT32_C(0x3B77E),
        UINT32_C(0x3BB7E),
        UINT32_C(0x3BF7E)
    };
    const uint8_t faulty_output = (uint8_t)(
        (scenery_sbox_correct(SECRET_DELTA) + 1u) & 0x0Fu
    );
    scenery_ctx ctx;
    scenery_infection_stats stats;
    capture_context capture;
    scenery_unknown_infection_partial_result partial;
    scenery_unknown_infection_active_candidate top[TOP_CAPACITY];
    uint64_t *scores;
    uint32_t actual_packed;
    size_t index;
    int status;

    memset(&capture, 0, sizeof(capture));
    memset(top, 0, sizeof(top));
    capture.capacity = (size_t)SAMPLE_COUNT;
    capture.ciphertexts = (uint8_t *)malloc(
        capture.capacity * SCENERY_BLOCK_SIZE
    );
    scores = (uint64_t *)calloc(
        (size_t)SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES,
        sizeof(*scores)
    );
    if (capture.ciphertexts == NULL || scores == NULL) {
        free(capture.ciphertexts);
        free(scores);
        return fail("allocation failed");
    }

    if (scenery_init(&ctx, key) != 0) {
        free(capture.ciphertexts);
        free(scores);
        return fail("scenery_init failed");
    }
    scenery_fault_reset();
    if (scenery_fault_inject(
            SECRET_SBOX,
            SECRET_DELTA,
            faulty_output) != 0) {
        free(capture.ciphertexts);
        free(scores);
        return fail("persistent fault injection failed");
    }

    scenery_unknown_infection_result_init(&capture.localization);
    status = scenery_infection_collect(
        &ctx,
        SAMPLE_COUNT,
        DATASET_SEED,
        &stats,
        capture_public_output,
        &capture
    );
    if (status != 0 || capture.count != (size_t)SAMPLE_COUNT) {
        free(capture.ciphertexts);
        free(scores);
        scenery_fault_reset();
        return fail("public infection dataset collection failed");
    }
    if (scenery_unknown_infection_identify_fault(&capture.localization) != 0 ||
        !capture.localization.success ||
        capture.localization.detected_sbox != SECRET_SBOX) {
        free(capture.ciphertexts);
        free(scores);
        scenery_fault_reset();
        return fail("Step 1 fault localization failed");
    }

    status = scenery_unknown_infection_rank_active_key_candidates(
        capture.ciphertexts,
        capture.count,
        capture.localization.detected_sbox,
        capture.localization.detected_public_minimum,
        scores,
        (size_t)SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES,
        top,
        TOP_CAPACITY,
        &partial
    );
    if (status != 0 || !partial.success) {
        free(capture.ciphertexts);
        free(scores);
        scenery_fault_reset();
        return fail("full 2^20 SEI ranking failed");
    }

    actual_packed = scenery_unknown_pack_round_key_active_words(
        ctx.round_keys[SCENERY_ROUNDS - 1u],
        SECRET_SBOX
    );
    if (partial.tested_candidates !=
            SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES ||
        partial.walsh_masks_evaluated != 15u) {
        free(capture.ciphertexts);
        free(scores);
        scenery_fault_reset();
        return fail("the exhaustive transform did not cover the full space");
    }
    if (partial.top_candidate_count != 4u ||
        partial.stored_top_candidate_count != 4u) {
        free(capture.ciphertexts);
        free(scores);
        scenery_fault_reset();
        return fail("the expected four structural maxima were not retained");
    }
    for (index = 0u; index < 4u; ++index) {
        if (top[index].packed_words != expected_top[index]) {
            free(capture.ciphertexts);
            free(scores);
            scenery_fault_reset();
            return fail("maximum-SEI candidate set differs from reference");
        }
    }
    if (!candidate_is_present(top, 4u, actual_packed)) {
        free(capture.ciphertexts);
        free(scores);
        scenery_fault_reset();
        return fail("actual active SK28 candidate is absent from rank 1");
    }
    if (scores[actual_packed] != direct_score_numerator(
            capture.ciphertexts,
            capture.count,
            SECRET_SBOX,
            actual_packed) ||
        scores[UINT32_C(0)] != direct_score_numerator(
            capture.ciphertexts,
            capture.count,
            SECRET_SBOX,
            UINT32_C(0))) {
        free(capture.ciphertexts);
        free(scores);
        scenery_fault_reset();
        return fail("Walsh score does not match direct partial decryption");
    }
    if (partial.top_score_numerator != UINT64_C(8340224) ||
        partial.second_score_numerator != UINT64_C(6884000) ||
        partial.sei_gap <= 0.0) {
        free(capture.ciphertexts);
        free(scores);
        scenery_fault_reset();
        return fail("exact SEI scores or positive separation differ");
    }
    if (partial.recovered_active_bits != 18u ||
        partial.known_bit_masks[0] != 0x0Fu ||
        partial.known_bit_masks[1] != 0x0Fu ||
        partial.known_bit_masks[2] != 0x03u ||
        partial.known_bit_masks[3] != 0x0Fu ||
        partial.known_bit_masks[4] != 0x0Fu) {
        free(capture.ciphertexts);
        free(scores);
        scenery_fault_reset();
        return fail("consensus is not the expected honest 18/20-bit result");
    }
    if (!partial.delta_recovered || partial.recovered_delta != SECRET_DELTA) {
        free(capture.ciphertexts);
        free(scores);
        scenery_fault_reset();
        return fail("unknown delta was not recovered uniquely");
    }

    puts("Scenario 4 / Step 2 unit test: exact full-space SEI ranking");
    printf("public infection samples:    %zu\n", capture.count);
    printf("detected S-box:              %u\n", partial.target_sbox);
    printf("public minimum:              0x%X\n", partial.public_minimum);
    printf("active S-box roles A..E:     %u,%u,%u,%u,%u\n",
           partial.active_sboxes[0], partial.active_sboxes[1],
           partial.active_sboxes[2], partial.active_sboxes[3],
           partial.active_sboxes[4]);
    printf("tested active candidates:    %" PRIu32 "\n",
           partial.tested_candidates);
    printf("rank-1 structural ties:      %zu\n",
           partial.top_candidate_count);
    puts("candidate  words(A,B,C,D,E)  SEI");
    for (index = 0u; index < partial.stored_top_candidate_count; ++index) {
        uint8_t words[SCENERY_UNKNOWN_ACTIVE_WORDS];

        scenery_unknown_unpack_active_words(top[index].packed_words, words);
        printf("0x%05" PRIX32 "    %X,%X,%X,%X,%X          %.12g%s\n",
               top[index].packed_words,
               words[0], words[1], words[2], words[3], words[4],
               top[index].sei,
               top[index].packed_words == actual_packed ? "  <-- actual" : "");
    }
    printf("top/second SEI:              %.12g / %.12g\n",
           partial.top_sei,
           partial.second_sei);
    printf("SEI gap:                     %.12g\n", partial.sei_gap);
    printf("known masks A..E:            %X,%X,%X,%X,%X\n",
           partial.known_bit_masks[0], partial.known_bit_masks[1],
           partial.known_bit_masks[2], partial.known_bit_masks[3],
           partial.known_bit_masks[4]);
    printf("recovered active key bits:   %zu/20\n",
           partial.recovered_active_bits);
    printf("recovered delta:             0x%X\n",
           partial.recovered_delta);

    free(capture.ciphertexts);
    free(scores);
    scenery_fault_reset();
    puts("PASS: Algorithm-4 full 2^20 SEI ranking recovered 18/20 active bits and the unique unknown delta without secret-key input.");
    return 0;
}
