#include "detection_dataset.h"
#include "known_detection_attack.h"
#include "persistent_fault.h"
#include "scenery.h"
#include "unknown_detection_attack.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define TARGET_INEFFECTIVE UINT64_C(512)
#define MAX_QUERIES        UINT64_C(20000)
#define TEST_SEED          UINT64_C(0x243F6A8885A308D3)
#define CANDIDATE_CAPACITY 32u

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
    memcpy(capture->ciphertexts[capture->count], ciphertext, SCENERY_BLOCK_SIZE);
    ++capture->count;
    return 0;
}

static int contains_candidate(
    const scenery_unknown_active_candidate *candidates,
    size_t count,
    uint32_t packed_words
)
{
    size_t index;

    for (index = 0u; index < count; ++index) {
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
    const uint8_t plaintext[SCENERY_BLOCK_SIZE] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF
    };
    const uint8_t secret_sbox = 5u;
    const uint8_t secret_delta = 0xBu;
    const uint8_t correct_output = scenery_sbox_correct(secret_delta);
    const uint8_t faulty_output =
        (uint8_t)((correct_output + 1u) & 0x0Fu);
    const uint32_t expected_candidates[4] = {
        UINT32_C(0x3B37E),
        UINT32_C(0x3B77E),
        UINT32_C(0x3BB7E),
        UINT32_C(0x3BF7E)
    };
    scenery_ctx ctx;
    scenery_detection_stats stats;
    scenery_unknown_detection_result localization;
    scenery_unknown_partial_result partial;
    const size_t profile_points[1] = { TARGET_INEFFECTIVE };
    scenery_unknown_prefix_profile profile[1];
    scenery_unknown_active_candidate candidates[CANDIDATE_CAPACITY];
    scenery_round_trace trace[SCENERY_ROUNDS];
    struct capture_context capture;
    uint8_t ciphertext[SCENERY_BLOCK_SIZE];
    uint32_t actual_packed;
    uint8_t actual_previous_word;
    uint8_t partial_previous_word;
    uint8_t actual_target_word;
    uint8_t expected_public_missing;
    size_t sample;
    size_t index;
    int status;

    memset(&capture, 0, sizeof(capture));
    memset(candidates, 0, sizeof(candidates));
    if (scenery_init(&ctx, key) != 0) {
        fputs("FAIL: scenery_init failed.\n", stderr);
        return 1;
    }

    actual_packed = scenery_unknown_pack_round_key_active_words(
        ctx.round_keys[SCENERY_ROUNDS - 1u],
        secret_sbox
    );
    if (actual_packed != UINT32_C(0x3BB7E)) {
        fprintf(stderr, "FAIL: unexpected packed active key %05" PRIX32 ".\n",
                actual_packed);
        return 1;
    }

    if (scenery_encrypt_block_trace(&ctx, plaintext, ciphertext, trace) != 0) {
        fputs("FAIL: trace encryption failed.\n", stderr);
        return 1;
    }
    actual_previous_word = scenery_extract_sbox_word(
        trace[SCENERY_ROUNDS - 2u].left_in,
        secret_sbox
    );
    partial_previous_word = scenery_unknown_partial_decrypt_previous_word(
        ciphertext,
        secret_sbox,
        actual_packed
    );
    if (actual_previous_word != partial_previous_word) {
        fprintf(stderr,
                "FAIL: partial decryption returned 0x%X, expected 0x%X.\n",
                partial_previous_word,
                actual_previous_word);
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

    scenery_unknown_detection_result_init(&localization);
    for (sample = 0u; sample < capture.count; ++sample) {
        if (scenery_unknown_detection_add_ciphertext(
                &localization,
                capture.ciphertexts[sample]) != 0) {
            fputs("FAIL: localization ingestion failed.\n", stderr);
            return 1;
        }
    }
    if (scenery_unknown_detection_identify_fault(&localization) != 0 ||
        !localization.success || localization.detected_sbox != secret_sbox) {
        fputs("FAIL: Step-1 localization failed.\n", stderr);
        return 1;
    }

    status = scenery_unknown_detection_filter_active_key_candidates(
        &capture.ciphertexts[0][0],
        capture.count,
        localization.detected_sbox,
        localization.detected_missing_value,
        candidates,
        CANDIDATE_CAPACITY,
        &partial
    );
    if (scenery_unknown_detection_profile_prefixes(
            &capture.ciphertexts[0][0],
            profile_points,
            1u,
            localization.detected_sbox,
            localization.detected_missing_value,
            profile) != 0) {
        fputs("FAIL: prefix profiling failed.\n", stderr);
        return 1;
    }

    actual_target_word = scenery_round_key_sbox_word(
        ctx.round_keys[SCENERY_ROUNDS - 1u],
        secret_sbox
    );
    expected_public_missing = (uint8_t)(secret_delta ^ actual_target_word);

    puts("Scenario 2 / Step 2 unit test: active-key candidate filtering");
    printf("public ineffective samples:  %zu\n", capture.count);
    printf("total oracle queries:        %" PRIu64 "\n", stats.total_queries);
    printf("detected S-box:              %u\n", localization.detected_sbox);
    printf("public missing value:        0x%X\n",
           localization.detected_missing_value);
    printf("active S-box roles A..E:     %u,%u,%u,%u,%u\n",
           partial.active_sboxes[0], partial.active_sboxes[1],
           partial.active_sboxes[2], partial.active_sboxes[3],
           partial.active_sboxes[4]);
    printf("tested active candidates:    %" PRIu32 "\n",
           partial.tested_candidates);
    printf("surviving candidates:        %zu\n",
           partial.surviving_candidate_count);
    puts("candidate  words(A,B,C,D,E)  missing-mask");
    for (index = 0u; index < partial.stored_candidate_count; ++index) {
        uint8_t words[SCENERY_UNKNOWN_ACTIVE_WORDS];
        scenery_unknown_unpack_active_words(candidates[index].packed_words, words);
        printf("0x%05" PRIX32 "    %X,%X,%X,%X,%X          0x%04X\n",
               candidates[index].packed_words,
               words[0], words[1], words[2], words[3], words[4],
               candidates[index].missing_mask);
    }
    printf("known masks A..E:            %X,%X,%X,%X,%X\n",
           partial.known_bit_masks[0], partial.known_bit_masks[1],
           partial.known_bit_masks[2], partial.known_bit_masks[3],
           partial.known_bit_masks[4]);
    printf("recovered active key bits:   %zu/20\n",
           partial.recovered_active_bits);
    printf("recovered delta:             0x%X\n", partial.recovered_delta);
    printf("actual packed active key:    0x%05" PRIX32 "\n", actual_packed);

    if (status != 0 || !partial.success ||
        localization.detected_missing_value != expected_public_missing ||
        partial.tested_candidates != SCENERY_UNKNOWN_ACTIVE_CANDIDATES ||
        partial.surviving_candidate_count != 4u ||
        partial.stored_candidate_count != 4u ||
        partial.candidate_missing_pairs != 4u ||
        partial.recovered_active_bits != 18u ||
        !partial.delta_recovered || partial.recovered_delta != secret_delta ||
        partial.known_bit_masks[0] != 0x0Fu ||
        partial.known_bit_masks[1] != 0x0Fu ||
        partial.known_bit_masks[2] != 0x03u ||
        partial.known_bit_masks[3] != 0x0Fu ||
        partial.known_bit_masks[4] != 0x0Fu ||
        profile[0].tested_candidates != partial.tested_candidates ||
        profile[0].candidate_sample_evaluations !=
            partial.candidate_sample_evaluations ||
        profile[0].surviving_candidate_count !=
            partial.surviving_candidate_count ||
        profile[0].recovered_active_bits != partial.recovered_active_bits ||
        !profile[0].delta_recovered ||
        profile[0].recovered_delta != partial.recovered_delta ||
        memcmp(profile[0].known_bit_masks, partial.known_bit_masks,
               sizeof(partial.known_bit_masks)) != 0 ||
        memcmp(profile[0].known_bit_values, partial.known_bit_values,
               sizeof(partial.known_bit_values)) != 0 ||
        !contains_candidate(candidates, partial.stored_candidate_count,
                            actual_packed)) {
        fputs("FAIL: Algorithm-2 active-key filtering was incorrect.\n", stderr);
        return 1;
    }
    for (index = 0u; index < 4u; ++index) {
        if (!contains_candidate(candidates, partial.stored_candidate_count,
                                expected_candidates[index])) {
            fprintf(stderr, "FAIL: expected candidate 0x%05" PRIX32
                    " is absent.\n", expected_candidates[index]);
            return 1;
        }
    }

    puts("PASS: partial decryption retained the four structural candidates, recovered 18/20 active bits, and recovered delta.");
    return 0;
}
