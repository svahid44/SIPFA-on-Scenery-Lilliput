#include "infection_dataset.h"
#include "known_detection_attack.h"
#include "known_infection_attack.h"
#include "persistent_fault.h"
#include "scenery.h"

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#define SAMPLES_PER_SBOX UINT64_C(32768)
#define BASE_SEED UINT64_C(0x13198A2E03707344)

struct attack_callback_context {
    scenery_known_infection_full_result *attack;
    uint8_t target_sbox;
};

static int add_public_ciphertext(
    uint64_t sample_index,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    void *user_data
)
{
    struct attack_callback_context *context =
        (struct attack_callback_context *)user_data;
    (void)sample_index;

    return scenery_known_infection_full_add_ciphertext(
        context->attack,
        context->target_sbox,
        ciphertext
    );
}

int main(void)
{
    const uint8_t key[SCENERY_KEY_SIZE] = {
        0x00, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99
    };
    const uint8_t delta = 0x5u;
    const uint8_t faulty_output = (uint8_t)(
        (scenery_sbox_correct(delta) + 1u) & 0x0Fu
    );
    scenery_ctx ctx;
    scenery_known_infection_full_result attack;
    scenery_infection_stats stats[SCENERY_ATTACK_SBOXES];
    uint32_t actual_sk28;
    size_t sbox;

    if (scenery_init(&ctx, key) != 0) {
        fputs("FAIL: scenery_init failed.\n", stderr);
        return 1;
    }
    scenery_known_infection_full_result_init(&attack, delta);

    for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
        const uint64_t seed = BASE_SEED +
            UINT64_C(0x9E3779B97F4A7C15) * (uint64_t)(sbox + 1u);
        struct attack_callback_context callback_context;
        int status;

        scenery_fault_reset();
        if (scenery_fault_inject((uint8_t)sbox, delta, faulty_output) != 0) {
            fprintf(stderr, "FAIL: fault injection failed for S-box %zu.\n", sbox);
            return 1;
        }
        callback_context.attack = &attack;
        callback_context.target_sbox = (uint8_t)sbox;
        status = scenery_infection_collect(
            &ctx,
            SAMPLES_PER_SBOX,
            seed,
            &stats[sbox],
            add_public_ciphertext,
            &callback_context
        );
        if (status != 0) {
            fprintf(stderr, "FAIL: infection collection returned %d.\n", status);
            return 1;
        }
    }
    scenery_fault_reset();

    if (scenery_known_infection_recover_full_round_key(&attack) != 0 ||
        !attack.success) {
        fprintf(stderr,
                "FAIL: full infection recovery failed (%zu/8 words).\n",
                attack.successful_sboxes);
        return 1;
    }

    actual_sk28 = ctx.round_keys[SCENERY_ROUNDS - 1u];
    puts("Scenario 3 / Step 2 unit test: complete infection-based SK28 recovery");
    puts("sbox  minimum  recovered  actual  gap  ineffective");
    for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
        const scenery_known_infection_result *word = &attack.per_sbox[sbox];
        const uint8_t actual_word = scenery_round_key_sbox_word(
            actual_sk28,
            (uint8_t)sbox
        );
        const uint64_t gap = word->second_minimum_count - word->minimum_count;

        printf("%4zu    0x%X       0x%X      0x%X   %3" PRIu64
               "  %11" PRIu64 "\n",
               sbox,
               word->minimum_value,
               word->recovered_round_key_word,
               actual_word,
               gap,
               stats[sbox].internal_ineffective_count);
        if (word->minimum_multiplicity != 1u ||
            word->recovered_round_key_word != actual_word) {
            fprintf(stderr, "FAIL: S-box %zu recovery mismatch.\n", sbox);
            return 1;
        }
    }

    printf("known delta:        0x%X\n", delta);
    printf("recovered SK28:     %08" PRIX32 "\n", attack.recovered_round_key);
    printf("actual SK28:        %08" PRIX32 "\n", actual_sk28);
    if (attack.recovered_round_key != actual_sk28) {
        fputs("FAIL: complete recovered SK28 mismatch.\n", stderr);
        return 1;
    }

    puts("PASS: eight Algorithm-3 minimum-frequency campaigns recovered the complete 32-bit SK28.");
    return 0;
}
