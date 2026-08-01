#include "detection_dataset.h"
#include "known_detection_attack.h"
#include "persistent_fault.h"
#include "scenery.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#define TARGET_PER_SBOX UINT64_C(4096)
#define MAX_QUERIES     UINT64_C(50000)
#define BASE_SEED       UINT64_C(0x6A09E667F3BCC909)

typedef struct collection_context {
    scenery_known_detection_full_result *result;
    uint8_t target_sbox;
} collection_context;

static int collect_for_full_attack(
    uint64_t query_index,
    uint64_t ineffective_index,
    const uint8_t plaintext[SCENERY_BLOCK_SIZE],
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    void *user_data
)
{
    collection_context *context = (collection_context *)user_data;

    (void)query_index;
    (void)ineffective_index;
    (void)plaintext;
    return scenery_known_detection_full_add_ciphertext(
        context->result,
        context->target_sbox,
        ciphertext
    );
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
    const uint8_t known_delta = 0x5u;
    const uint8_t faulty_output = (uint8_t)(
        (scenery_sbox_correct(known_delta) + 1u) & 0x0Fu
    );
    scenery_ctx ctx;
    scenery_known_detection_full_result result;
    scenery_detection_stats stats[SCENERY_ATTACK_SBOXES];
    uint32_t actual_round_key;
    uint64_t total_queries = 0u;
    size_t sbox;
    int status;

    if (scenery_init(&ctx, key) != 0) {
        return fail("scenery_init failed");
    }

    scenery_known_detection_full_result_init(&result, known_delta);

    for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
        collection_context context;
        const uint64_t seed = BASE_SEED ^
            (UINT64_C(0x9E3779B97F4A7C15) * (uint64_t)(sbox + 1u));

        scenery_fault_reset();
        if (scenery_fault_inject(
                (uint8_t)sbox,
                known_delta,
                faulty_output) != 0) {
            return fail("persistent fault injection failed");
        }

        context.result = &result;
        context.target_sbox = (uint8_t)sbox;
        status = scenery_detection_collect(
            &ctx,
            TARGET_PER_SBOX,
            MAX_QUERIES,
            seed,
            &stats[sbox],
            collect_for_full_attack,
            &context
        );
        if (status != 0) {
            return fail("one target-S-box campaign failed");
        }
        if (result.per_sbox[sbox].sample_count != TARGET_PER_SBOX) {
            return fail("one target-S-box histogram is incomplete");
        }
        total_queries += stats[sbox].total_queries;
    }

    status = scenery_known_detection_recover_full_round_key(&result);
    actual_round_key = ctx.round_keys[SCENERY_ROUNDS - 1u];

    if (status != 0 || !result.success ||
        result.successful_sboxes != SCENERY_ATTACK_SBOXES) {
        return fail("full known-fault recovery was not unique");
    }
    if (result.recovered_round_key != actual_round_key) {
        return fail("recovered complete SK28 differs from ground truth");
    }

    puts("sbox  missing  recovered_word  actual_word  queries");
    for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
        const uint8_t actual_word = scenery_round_key_sbox_word(
            actual_round_key,
            (uint8_t)sbox
        );
        if (result.per_sbox[sbox].missing_count != 1u ||
            result.recovered_words[sbox] != actual_word) {
            return fail("one recovered S-box word is incorrect");
        }
        printf("%4zu  0x%X      0x%X             0x%X          %" PRIu64 "\n",
               sbox,
               result.per_sbox[sbox].missing_values[0],
               result.recovered_words[sbox],
               actual_word,
               stats[sbox].total_queries);
    }

    printf("known delta:        0x%X\n", known_delta);
    printf("total ineffective:  %" PRIu64 "\n",
           TARGET_PER_SBOX * SCENERY_ATTACK_SBOXES);
    printf("total queries:      %" PRIu64 "\n", total_queries);
    printf("recovered SK28:     %08" PRIX32 "\n",
           result.recovered_round_key);
    printf("actual SK28:        %08" PRIX32 "\n", actual_round_key);

    scenery_fault_reset();
    puts("PASS: eight Algorithm-1 campaigns recovered the complete 32-bit SK28.");
    return 0;
}
