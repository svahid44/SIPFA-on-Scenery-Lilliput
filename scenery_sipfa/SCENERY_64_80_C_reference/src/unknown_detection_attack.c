#include "unknown_detection_attack.h"

#include <stdlib.h>
#include <string.h>

#include "known_detection_attack.h"
#include "persistent_fault.h"

typedef struct scenery_unknown_precomputed_sample {
    uint8_t right_target_word;
    uint8_t contribution[SCENERY_UNKNOWN_ACTIVE_WORDS]
                        [SCENERY_UNKNOWN_DETECTION_DOMAIN];
} scenery_unknown_precomputed_sample;

static uint32_t load32_be(const uint8_t input[4])
{
    return ((uint32_t)input[0] << 24) |
           ((uint32_t)input[1] << 16) |
           ((uint32_t)input[2] <<  8) |
           ((uint32_t)input[3]);
}

static unsigned int popcount16(uint16_t value)
{
    unsigned int count = 0u;

    while (value != 0u) {
        count += (unsigned int)(value & UINT16_C(1));
        value = (uint16_t)(value >> 1);
    }
    return count;
}

static unsigned int popcount4(uint8_t value)
{
    unsigned int count = 0u;

    value &= 0x0Fu;
    while (value != 0u) {
        count += (unsigned int)(value & 1u);
        value = (uint8_t)(value >> 1);
    }
    return count;
}

static uint8_t role_contribution(uint8_t role, uint8_t substituted)
{
    const uint8_t bit0 = (uint8_t)(substituted & 1u);
    const uint8_t bit1 = (uint8_t)((substituted >> 1) & 1u);
    const uint8_t bit2 = (uint8_t)((substituted >> 2) & 1u);
    const uint8_t bit3 = (uint8_t)((substituted >> 3) & 1u);

    switch (role) {
    case 0u: /* A = j-1 */
        return (uint8_t)((bit1 << 0) | (bit1 << 1) |
                         (bit2 << 2) | (bit2 << 3));
    case 1u: /* B = j */
        return (uint8_t)((bit1 << 1) | (bit2 << 2));
    case 2u: /* C = j+2 */
        return bit0;
    case 3u: /* D = j+3 */
        return (uint8_t)((bit0 << 0) | (bit0 << 1) | (bit3 << 3));
    case 4u: /* E = j+4 */
        return (uint8_t)((bit3 << 2) | (bit3 << 3));
    default:
        return 0u;
    }
}

static uint8_t partial_mixed_target_word(
    const uint8_t left_words[SCENERY_UNKNOWN_ACTIVE_WORDS],
    const uint8_t key_words[SCENERY_UNKNOWN_ACTIVE_WORDS]
)
{
    uint8_t mixed = 0u;
    size_t role;

    for (role = 0u; role < SCENERY_UNKNOWN_ACTIVE_WORDS; ++role) {
        const uint8_t substituted = scenery_sbox_correct(
            (uint8_t)(left_words[role] ^ key_words[role])
        );
        mixed ^= role_contribution((uint8_t)role, substituted);
    }
    return (uint8_t)(mixed & 0x0Fu);
}

void scenery_unknown_detection_result_init(
    scenery_unknown_detection_result *result
)
{
    if (result != NULL) {
        memset(result, 0, sizeof(*result));
    }
}

int scenery_unknown_detection_add_ciphertext(
    scenery_unknown_detection_result *result,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE]
)
{
    size_t sbox;

    if (result == NULL || ciphertext == NULL) {
        return -1;
    }

    for (sbox = 0u; sbox < SCENERY_UNKNOWN_DETECTION_SBOXES; ++sbox) {
        const uint8_t value = scenery_last_round_public_word(
            ciphertext,
            (uint8_t)sbox
        );
        ++result->histogram[sbox][value];
    }
    ++result->sample_count;
    return 0;
}

int scenery_unknown_detection_identify_fault(
    scenery_unknown_detection_result *result
)
{
    size_t sbox;

    if (result == NULL || result->sample_count == 0u) {
        return -1;
    }

    result->total_missing_count = 0u;
    result->detected_sbox = 0u;
    result->detected_missing_value = 0u;
    result->success = 0;
    memset(
        result->missing_count_per_sbox,
        0,
        sizeof(result->missing_count_per_sbox)
    );
    memset(result->missing_values, 0, sizeof(result->missing_values));

    for (sbox = 0u; sbox < SCENERY_UNKNOWN_DETECTION_SBOXES; ++sbox) {
        size_t value;

        for (value = 0u; value < SCENERY_UNKNOWN_DETECTION_DOMAIN; ++value) {
            if (result->histogram[sbox][value] == 0u) {
                const size_t index = result->missing_count_per_sbox[sbox];

                result->missing_values[sbox][index] = (uint8_t)value;
                ++result->missing_count_per_sbox[sbox];
                ++result->total_missing_count;
                result->detected_sbox = (uint8_t)sbox;
                result->detected_missing_value = (uint8_t)value;
            }
        }
    }

    if (result->total_missing_count != 1u) {
        return 1;
    }

    result->success = 1;
    return 0;
}

int scenery_unknown_active_sboxes(
    uint8_t target_sbox,
    uint8_t active_sboxes[SCENERY_UNKNOWN_ACTIVE_WORDS]
)
{
    if (target_sbox >= SCENERY_UNKNOWN_DETECTION_SBOXES ||
        active_sboxes == NULL) {
        return -1;
    }

    active_sboxes[0] = (uint8_t)((target_sbox + 7u) & 7u);
    active_sboxes[1] = target_sbox;
    active_sboxes[2] = (uint8_t)((target_sbox + 2u) & 7u);
    active_sboxes[3] = (uint8_t)((target_sbox + 3u) & 7u);
    active_sboxes[4] = (uint8_t)((target_sbox + 4u) & 7u);
    return 0;
}

uint32_t scenery_unknown_pack_active_words(
    const uint8_t words[SCENERY_UNKNOWN_ACTIVE_WORDS]
)
{
    uint32_t packed = UINT32_C(0);
    size_t role;

    if (words == NULL) {
        return UINT32_C(0);
    }
    for (role = 0u; role < SCENERY_UNKNOWN_ACTIVE_WORDS; ++role) {
        packed |= (uint32_t)(words[role] & 0x0Fu) << (4u * role);
    }
    return packed;
}

void scenery_unknown_unpack_active_words(
    uint32_t packed_words,
    uint8_t words[SCENERY_UNKNOWN_ACTIVE_WORDS]
)
{
    size_t role;

    if (words == NULL) {
        return;
    }
    for (role = 0u; role < SCENERY_UNKNOWN_ACTIVE_WORDS; ++role) {
        words[role] = (uint8_t)((packed_words >> (4u * role)) & 0x0Fu);
    }
}

uint32_t scenery_unknown_pack_round_key_active_words(
    uint32_t round_key,
    uint8_t target_sbox
)
{
    uint8_t active_sboxes[SCENERY_UNKNOWN_ACTIVE_WORDS];
    uint8_t words[SCENERY_UNKNOWN_ACTIVE_WORDS];
    size_t role;

    if (scenery_unknown_active_sboxes(target_sbox, active_sboxes) != 0) {
        return UINT32_C(0);
    }
    for (role = 0u; role < SCENERY_UNKNOWN_ACTIVE_WORDS; ++role) {
        words[role] = scenery_round_key_sbox_word(
            round_key,
            active_sboxes[role]
        );
    }
    return scenery_unknown_pack_active_words(words);
}

uint8_t scenery_unknown_partial_decrypt_previous_word(
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE],
    uint8_t target_sbox,
    uint32_t packed_active_words
)
{
    uint8_t active_sboxes[SCENERY_UNKNOWN_ACTIVE_WORDS];
    uint8_t left_words[SCENERY_UNKNOWN_ACTIVE_WORDS];
    uint8_t key_words[SCENERY_UNKNOWN_ACTIVE_WORDS];
    uint8_t right_target;
    size_t role;

    if (ciphertext == NULL ||
        scenery_unknown_active_sboxes(target_sbox, active_sboxes) != 0) {
        return 0u;
    }

    for (role = 0u; role < SCENERY_UNKNOWN_ACTIVE_WORDS; ++role) {
        left_words[role] = scenery_last_round_public_word(
            ciphertext,
            active_sboxes[role]
        );
    }
    scenery_unknown_unpack_active_words(packed_active_words, key_words);

    right_target = scenery_extract_sbox_word(
        load32_be(ciphertext + 4u),
        target_sbox
    );
    return (uint8_t)(right_target ^
                     partial_mixed_target_word(left_words, key_words));
}

static int precompute_samples(
    const uint8_t *ciphertexts,
    size_t sample_count,
    uint8_t target_sbox,
    const uint8_t active_sboxes[SCENERY_UNKNOWN_ACTIVE_WORDS],
    scenery_unknown_precomputed_sample *samples
)
{
    size_t sample;

    for (sample = 0u; sample < sample_count; ++sample) {
        const uint8_t *ciphertext = ciphertexts + sample * SCENERY_BLOCK_SIZE;
        const uint32_t right = load32_be(ciphertext + 4u);
        size_t role;

        samples[sample].right_target_word = scenery_extract_sbox_word(
            right,
            target_sbox
        );

        for (role = 0u; role < SCENERY_UNKNOWN_ACTIVE_WORDS; ++role) {
            const uint8_t public_word = scenery_last_round_public_word(
                ciphertext,
                active_sboxes[role]
            );
            size_t guess;

            for (guess = 0u; guess < SCENERY_UNKNOWN_DETECTION_DOMAIN; ++guess) {
                const uint8_t substituted = scenery_sbox_correct(
                    (uint8_t)(public_word ^ (uint8_t)guess)
                );
                samples[sample].contribution[role][guess] =
                    role_contribution((uint8_t)role, substituted);
            }
        }
    }
    return 0;
}

static void summarize_surviving_candidates(
    const scenery_unknown_active_candidate *candidates,
    size_t candidate_count,
    scenery_unknown_partial_result *result
)
{
    uint8_t first_words[SCENERY_UNKNOWN_ACTIVE_WORDS];
    uint8_t differences[SCENERY_UNKNOWN_ACTIVE_WORDS] = { 0u, 0u, 0u, 0u, 0u };
    size_t index;
    size_t role;

    if (candidate_count == 0u || candidates == NULL || result == NULL) {
        return;
    }

    scenery_unknown_unpack_active_words(candidates[0].packed_words, first_words);
    for (index = 1u; index < candidate_count; ++index) {
        uint8_t words[SCENERY_UNKNOWN_ACTIVE_WORDS];
        scenery_unknown_unpack_active_words(candidates[index].packed_words, words);
        for (role = 0u; role < SCENERY_UNKNOWN_ACTIVE_WORDS; ++role) {
            differences[role] |= (uint8_t)(first_words[role] ^ words[role]);
        }
    }

    result->recovered_active_bits = 0u;
    for (role = 0u; role < SCENERY_UNKNOWN_ACTIVE_WORDS; ++role) {
        result->known_bit_masks[role] =
            (uint8_t)((~differences[role]) & 0x0Fu);
        result->known_bit_values[role] =
            (uint8_t)(first_words[role] & result->known_bit_masks[role]);
        result->recovered_active_bits +=
            popcount4(result->known_bit_masks[role]);
    }

    /* Role B is the target S-box word itself. */
    if (result->known_bit_masks[1] == 0x0Fu) {
        result->recovered_delta = (uint8_t)(
            result->public_missing_value ^ result->known_bit_values[1]
        );
        result->delta_recovered = 1;
    }
}

int scenery_unknown_detection_filter_active_key_candidates(
    const uint8_t *ciphertexts,
    size_t sample_count,
    uint8_t target_sbox,
    uint8_t public_missing_value,
    scenery_unknown_active_candidate *candidates,
    size_t candidate_capacity,
    scenery_unknown_partial_result *result
)
{
    scenery_unknown_precomputed_sample *samples;
    uint8_t active_sboxes[SCENERY_UNKNOWN_ACTIVE_WORDS];
    uint32_t packed_candidate;

    if (ciphertexts == NULL || sample_count == 0u ||
        target_sbox >= SCENERY_UNKNOWN_DETECTION_SBOXES ||
        public_missing_value >= SCENERY_UNKNOWN_DETECTION_DOMAIN ||
        result == NULL || (candidate_capacity > 0u && candidates == NULL)) {
        return -1;
    }
    if (scenery_unknown_active_sboxes(target_sbox, active_sboxes) != 0) {
        return -1;
    }

    memset(result, 0, sizeof(*result));
    result->sample_count = sample_count;
    result->target_sbox = target_sbox;
    result->public_missing_value = public_missing_value;
    memcpy(result->active_sboxes, active_sboxes, sizeof(active_sboxes));

    samples = (scenery_unknown_precomputed_sample *)malloc(
        sample_count * sizeof(*samples)
    );
    if (samples == NULL) {
        return -2;
    }
    (void)precompute_samples(
        ciphertexts,
        sample_count,
        target_sbox,
        active_sboxes,
        samples
    );

    for (packed_candidate = UINT32_C(0);
         packed_candidate < SCENERY_UNKNOWN_ACTIVE_CANDIDATES;
         ++packed_candidate) {
        const uint8_t word_a = (uint8_t)( packed_candidate        & 0x0Fu);
        const uint8_t word_b = (uint8_t)((packed_candidate >>  4) & 0x0Fu);
        const uint8_t word_c = (uint8_t)((packed_candidate >>  8) & 0x0Fu);
        const uint8_t word_d = (uint8_t)((packed_candidate >> 12) & 0x0Fu);
        const uint8_t word_e = (uint8_t)((packed_candidate >> 16) & 0x0Fu);
        uint16_t seen_mask = UINT16_C(0);
        size_t sample;

        for (sample = 0u; sample < sample_count; ++sample) {
            const uint8_t mixed = (uint8_t)(
                samples[sample].contribution[0][word_a] ^
                samples[sample].contribution[1][word_b] ^
                samples[sample].contribution[2][word_c] ^
                samples[sample].contribution[3][word_d] ^
                samples[sample].contribution[4][word_e]
            );
            const uint8_t previous_word = (uint8_t)(
                samples[sample].right_target_word ^ mixed
            );

            seen_mask |= (uint16_t)(UINT16_C(1) << previous_word);
            ++result->candidate_sample_evaluations;
            if (seen_mask == UINT16_C(0xFFFF)) {
                break;
            }
        }

        if (seen_mask != UINT16_C(0xFFFF)) {
            const uint16_t missing_mask = (uint16_t)(~seen_mask);
            const uint8_t missing_count = (uint8_t)popcount16(missing_mask);

            if (result->stored_candidate_count < candidate_capacity) {
                scenery_unknown_active_candidate *stored =
                    &candidates[result->stored_candidate_count];
                stored->packed_words = packed_candidate;
                stored->missing_mask = missing_mask;
                stored->missing_count = missing_count;
                ++result->stored_candidate_count;
            }
            ++result->surviving_candidate_count;
            result->candidate_missing_pairs += missing_count;
        }
    }
    result->tested_candidates = SCENERY_UNKNOWN_ACTIVE_CANDIDATES;
    free(samples);

    if (result->stored_candidate_count == result->surviving_candidate_count) {
        summarize_surviving_candidates(
            candidates,
            result->stored_candidate_count,
            result
        );
    }
    result->success = result->surviving_candidate_count > 0u;
    return 0;
}

int scenery_unknown_detection_profile_prefixes(
    const uint8_t *ciphertexts,
    const size_t *sample_points,
    size_t point_count,
    uint8_t target_sbox,
    uint8_t public_missing_value,
    scenery_unknown_prefix_profile *profiles
)
{
    scenery_unknown_precomputed_sample *samples;
    uint8_t active_sboxes[SCENERY_UNKNOWN_ACTIVE_WORDS];
    uint8_t *first_words;
    uint8_t *differences;
    uint8_t *has_first;
    size_t maximum_samples;
    uint32_t packed_candidate;
    size_t point;

    if (ciphertexts == NULL || sample_points == NULL || point_count == 0u ||
        profiles == NULL || target_sbox >= SCENERY_UNKNOWN_DETECTION_SBOXES ||
        public_missing_value >= SCENERY_UNKNOWN_DETECTION_DOMAIN ||
        scenery_unknown_active_sboxes(target_sbox, active_sboxes) != 0) {
        return -1;
    }
    for (point = 0u; point < point_count; ++point) {
        if (sample_points[point] == 0u ||
            (point > 0u && sample_points[point] <= sample_points[point - 1u])) {
            return -1;
        }
    }
    maximum_samples = sample_points[point_count - 1u];

    samples = (scenery_unknown_precomputed_sample *)malloc(
        maximum_samples * sizeof(*samples)
    );
    first_words = (uint8_t *)calloc(
        point_count * SCENERY_UNKNOWN_ACTIVE_WORDS,
        sizeof(*first_words)
    );
    differences = (uint8_t *)calloc(
        point_count * SCENERY_UNKNOWN_ACTIVE_WORDS,
        sizeof(*differences)
    );
    has_first = (uint8_t *)calloc(point_count, sizeof(*has_first));
    if (samples == NULL || first_words == NULL || differences == NULL ||
        has_first == NULL) {
        free(samples);
        free(first_words);
        free(differences);
        free(has_first);
        return -2;
    }

    memset(profiles, 0, point_count * sizeof(*profiles));
    for (point = 0u; point < point_count; ++point) {
        profiles[point].sample_count = sample_points[point];
        profiles[point].tested_candidates = SCENERY_UNKNOWN_ACTIVE_CANDIDATES;
    }
    (void)precompute_samples(
        ciphertexts,
        maximum_samples,
        target_sbox,
        active_sboxes,
        samples
    );

    for (packed_candidate = UINT32_C(0);
         packed_candidate < SCENERY_UNKNOWN_ACTIVE_CANDIDATES;
         ++packed_candidate) {
        const uint8_t word_a = (uint8_t)( packed_candidate        & 0x0Fu);
        const uint8_t word_b = (uint8_t)((packed_candidate >>  4) & 0x0Fu);
        const uint8_t word_c = (uint8_t)((packed_candidate >>  8) & 0x0Fu);
        const uint8_t word_d = (uint8_t)((packed_candidate >> 12) & 0x0Fu);
        const uint8_t word_e = (uint8_t)((packed_candidate >> 16) & 0x0Fu);
        uint16_t seen_mask = UINT16_C(0);
        size_t first_full_count = 0u;
        size_t sample;

        for (sample = 0u; sample < maximum_samples; ++sample) {
            const uint8_t mixed = (uint8_t)(
                samples[sample].contribution[0][word_a] ^
                samples[sample].contribution[1][word_b] ^
                samples[sample].contribution[2][word_c] ^
                samples[sample].contribution[3][word_d] ^
                samples[sample].contribution[4][word_e]
            );
            const uint8_t previous_word = (uint8_t)(
                samples[sample].right_target_word ^ mixed
            );

            seen_mask |= (uint16_t)(UINT16_C(1) << previous_word);
            if (seen_mask == UINT16_C(0xFFFF)) {
                first_full_count = sample + 1u;
                break;
            }
        }

        for (point = 0u; point < point_count; ++point) {
            scenery_unknown_prefix_profile *profile = &profiles[point];
            const size_t prefix = sample_points[point];
            const size_t evaluations = first_full_count == 0u ||
                first_full_count > prefix ? prefix : first_full_count;

            profile->candidate_sample_evaluations += evaluations;
            if (first_full_count == 0u || first_full_count > prefix) {
                uint8_t words[SCENERY_UNKNOWN_ACTIVE_WORDS];
                size_t role;

                scenery_unknown_unpack_active_words(packed_candidate, words);
                ++profile->surviving_candidate_count;
                if (!has_first[point]) {
                    memcpy(
                        first_words + point * SCENERY_UNKNOWN_ACTIVE_WORDS,
                        words,
                        SCENERY_UNKNOWN_ACTIVE_WORDS
                    );
                    has_first[point] = 1u;
                } else {
                    for (role = 0u; role < SCENERY_UNKNOWN_ACTIVE_WORDS; ++role) {
                        differences[
                            point * SCENERY_UNKNOWN_ACTIVE_WORDS + role
                        ] |= (uint8_t)(
                            first_words[
                                point * SCENERY_UNKNOWN_ACTIVE_WORDS + role
                            ] ^ words[role]
                        );
                    }
                }
            }
        }
    }

    for (point = 0u; point < point_count; ++point) {
        scenery_unknown_prefix_profile *profile = &profiles[point];
        size_t role;

        if (!has_first[point]) {
            continue;
        }
        for (role = 0u; role < SCENERY_UNKNOWN_ACTIVE_WORDS; ++role) {
            const uint8_t mask = (uint8_t)(
                (~differences[point * SCENERY_UNKNOWN_ACTIVE_WORDS + role]) &
                0x0Fu
            );
            const uint8_t value = (uint8_t)(
                first_words[point * SCENERY_UNKNOWN_ACTIVE_WORDS + role] & mask
            );
            profile->known_bit_masks[role] = mask;
            profile->known_bit_values[role] = value;
            profile->recovered_active_bits += popcount4(mask);
        }
        if (profile->known_bit_masks[1] == 0x0Fu) {
            profile->recovered_delta = (uint8_t)(
                public_missing_value ^ profile->known_bit_values[1]
            );
            profile->delta_recovered = 1;
        }
    }

    free(samples);
    free(first_words);
    free(differences);
    free(has_first);
    return 0;
}

