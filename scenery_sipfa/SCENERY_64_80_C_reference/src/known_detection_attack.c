#include "known_detection_attack.h"

#include <string.h>

static uint32_t load32_be(const uint8_t input[4])
{
    return ((uint32_t)input[0] << 24) |
           ((uint32_t)input[1] << 16) |
           ((uint32_t)input[2] <<  8) |
           ((uint32_t)input[3]);
}

static void store32_be(uint8_t output[4], uint32_t value)
{
    output[0] = (uint8_t)(value >> 24);
    output[1] = (uint8_t)(value >> 16);
    output[2] = (uint8_t)(value >>  8);
    output[3] = (uint8_t)value;
}

uint8_t scenery_extract_sbox_word(uint32_t bitsliced_word, uint8_t sbox_index)
{
    uint8_t rows[4];
    uint8_t value = 0u;
    unsigned int row;

    if (sbox_index >= SCENERY_ATTACK_SBOXES) {
        return 0u;
    }

    store32_be(rows, bitsliced_word);
    for (row = 0u; row < 4u; ++row) {
        value |= (uint8_t)(((rows[row] >> sbox_index) & 1u) << row);
    }
    return value;
}

uint8_t scenery_last_round_public_word(
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    uint8_t sbox_index
)
{
    if (ciphertext == NULL || sbox_index >= SCENERY_ATTACK_SBOXES) {
        return 0u;
    }

    /* C_left = R_29 = L_28 for the final Feistel round. */
    return scenery_extract_sbox_word(load32_be(ciphertext), sbox_index);
}

void scenery_known_detection_result_init(
    scenery_known_detection_result *result,
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

int scenery_known_detection_add_ciphertext(
    scenery_known_detection_result *result,
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

size_t scenery_histogram_missing_values(
    const uint64_t histogram[SCENERY_ATTACK_DOMAIN],
    uint8_t missing_values[SCENERY_ATTACK_DOMAIN]
)
{
    size_t count = 0u;
    size_t value;

    if (histogram == NULL || missing_values == NULL) {
        return 0u;
    }

    for (value = 0u; value < SCENERY_ATTACK_DOMAIN; ++value) {
        if (histogram[value] == 0u) {
            missing_values[count] = (uint8_t)value;
            ++count;
        }
    }
    return count;
}

int scenery_known_detection_recover_word(
    scenery_known_detection_result *result
)
{
    if (result == NULL || result->sample_count == 0u ||
        result->target_sbox >= SCENERY_ATTACK_SBOXES ||
        result->known_delta >= SCENERY_ATTACK_DOMAIN) {
        return -1;
    }

    result->missing_count = scenery_histogram_missing_values(
        result->histogram,
        result->missing_values
    );
    result->success = 0;
    result->recovered_round_key_word = 0u;

    if (result->missing_count != 1u) {
        return 1;
    }

    result->recovered_round_key_word = (uint8_t)(
        result->missing_values[0] ^ result->known_delta
    );
    result->success = 1;
    return 0;
}

uint8_t scenery_round_key_sbox_word(
    uint32_t round_key,
    uint8_t sbox_index
)
{
    return scenery_extract_sbox_word(round_key, sbox_index);
}

uint32_t scenery_compose_round_key_sbox_words(
    const uint8_t words[SCENERY_ATTACK_SBOXES]
)
{
    uint8_t rows[4] = { 0u, 0u, 0u, 0u };
    unsigned int sbox;
    unsigned int row;

    if (words == NULL) {
        return UINT32_C(0);
    }

    for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
        const uint8_t word = (uint8_t)(words[sbox] & 0x0Fu);
        for (row = 0u; row < 4u; ++row) {
            rows[row] |= (uint8_t)(((word >> row) & 1u) << sbox);
        }
    }
    return load32_be(rows);
}

void scenery_known_detection_full_result_init(
    scenery_known_detection_full_result *result,
    uint8_t known_delta
)
{
    size_t sbox;

    if (result == NULL) {
        return;
    }

    memset(result, 0, sizeof(*result));
    for (sbox = 0u; sbox < SCENERY_ATTACK_SBOXES; ++sbox) {
        scenery_known_detection_result_init(
            &result->per_sbox[sbox],
            (uint8_t)sbox,
            known_delta
        );
    }
}

int scenery_known_detection_full_add_ciphertext(
    scenery_known_detection_full_result *result,
    uint8_t target_sbox,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE]
)
{
    if (result == NULL || target_sbox >= SCENERY_ATTACK_SBOXES) {
        return -1;
    }
    return scenery_known_detection_add_ciphertext(
        &result->per_sbox[target_sbox],
        ciphertext
    );
}

int scenery_known_detection_recover_full_round_key(
    scenery_known_detection_full_result *result
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
        const int status = scenery_known_detection_recover_word(
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
