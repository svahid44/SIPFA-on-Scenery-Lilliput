#include "known_infection_attack.h"

#include <stdint.h>
#include <string.h>

void scenery_known_infection_result_init(
    scenery_known_infection_result *result,
    uint8_t target_sbox,
    uint8_t known_delta
)
{
    if (result == NULL) {
        return;
    }

    memset(result, 0, sizeof(*result));
    result->target_sbox = target_sbox;
    result->known_delta = (uint8_t)(known_delta & 0x0Fu);
}

int scenery_known_infection_add_ciphertext(
    scenery_known_infection_result *result,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE]
)
{
    uint8_t value;

    if (result == NULL || ciphertext == NULL ||
        result->target_sbox >= SCENERY_ATTACK_SBOXES ||
        result->known_delta >= SCENERY_ATTACK_DOMAIN) {
        return -1;
    }

    value = scenery_last_round_public_word(ciphertext, result->target_sbox);
    ++result->histogram[value];
    ++result->sample_count;
    return 0;
}

int scenery_known_infection_recover_word(
    scenery_known_infection_result *result
)
{
    uint64_t minimum = UINT64_MAX;
    uint64_t second_minimum = UINT64_MAX;
    size_t minimum_multiplicity = 0u;
    uint8_t minimum_value = 0u;
    size_t value;

    if (result == NULL || result->sample_count == 0u ||
        result->target_sbox >= SCENERY_ATTACK_SBOXES ||
        result->known_delta >= SCENERY_ATTACK_DOMAIN) {
        return -1;
    }

    for (value = 0u; value < SCENERY_ATTACK_DOMAIN; ++value) {
        const uint64_t count = result->histogram[value];
        if (count < minimum) {
            minimum = count;
            minimum_value = (uint8_t)value;
        }
    }

    for (value = 0u; value < SCENERY_ATTACK_DOMAIN; ++value) {
        const uint64_t count = result->histogram[value];
        if (count == minimum) {
            ++minimum_multiplicity;
        } else if (count < second_minimum) {
            second_minimum = count;
        }
    }

    if (second_minimum == UINT64_MAX) {
        second_minimum = minimum;
    }

    result->minimum_value = minimum_value;
    result->minimum_count = minimum;
    result->second_minimum_count = second_minimum;
    result->minimum_multiplicity = minimum_multiplicity;
    result->recovered_round_key_word = 0u;
    result->success = 0;

    if (minimum_multiplicity != 1u) {
        return 1;
    }

    result->recovered_round_key_word = (uint8_t)(
        minimum_value ^ result->known_delta
    );
    result->success = 1;
    return 0;
}


void scenery_known_infection_full_result_init(
    scenery_known_infection_full_result *result,
    uint8_t known_delta
)
{
    size_t sbox;

    if (result == NULL) {
        return;
    }

    memset(result, 0, sizeof(*result));
    for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
        scenery_known_infection_result_init(
            &result->per_sbox[sbox],
            (uint8_t)sbox,
            known_delta
        );
    }
}

int scenery_known_infection_full_add_ciphertext(
    scenery_known_infection_full_result *result,
    uint8_t target_sbox,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE]
)
{
    if (result == NULL || target_sbox >= SCENERY_ATTACK_SBOXES) {
        return -1;
    }
    return scenery_known_infection_add_ciphertext(
        &result->per_sbox[target_sbox],
        ciphertext
    );
}

int scenery_known_infection_recover_full_round_key(
    scenery_known_infection_full_result *result
)
{
    size_t sbox;

    if (result == NULL) {
        return -1;
    }

    result->successful_sboxes = 0u;
    result->recovered_round_key = UINT32_C(0);
    result->success = 0;
    memset(result->recovered_words, 0, sizeof(result->recovered_words));

    for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
        const int status = scenery_known_infection_recover_word(
            &result->per_sbox[sbox]
        );
        if (status != 0 || !result->per_sbox[sbox].success) {
            return 1;
        }
        result->recovered_words[sbox] =
            result->per_sbox[sbox].recovered_round_key_word;
        ++result->successful_sboxes;
    }

    result->recovered_round_key = scenery_compose_round_key_sbox_words(
        result->recovered_words
    );
    result->success = 1;
    return 0;
}
