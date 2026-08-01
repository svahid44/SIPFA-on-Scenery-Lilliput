#include "unknown_infection_attack.h"

#include <float.h>
#include <stdlib.h>
#include <string.h>

#include "known_detection_attack.h"
#include "persistent_fault.h"

static double squared_euclidean_imbalance(
    const uint64_t histogram[SCENERY_UNKNOWN_INFECTION_DOMAIN],
    uint64_t sample_count
)
{
    const double uniform = 1.0 / (double)SCENERY_UNKNOWN_INFECTION_DOMAIN;
    const double denominator = (double)sample_count;
    double score = 0.0;
    size_t value;

    for (value = 0u; value < SCENERY_UNKNOWN_INFECTION_DOMAIN; ++value) {
        const double probability =
            (double)histogram[value] / denominator;
        const double difference = probability - uniform;
        score += difference * difference;
    }
    return score;
}

static void characterize_minimum(
    const uint64_t histogram[SCENERY_UNKNOWN_INFECTION_DOMAIN],
    uint8_t *minimum_value,
    uint64_t *minimum_count,
    uint64_t *second_minimum_count,
    size_t *minimum_multiplicity
)
{
    uint64_t minimum = UINT64_MAX;
    uint64_t second = UINT64_MAX;
    size_t multiplicity = 0u;
    uint8_t minimum_index = 0u;
    size_t value;

    for (value = 0u; value < SCENERY_UNKNOWN_INFECTION_DOMAIN; ++value) {
        const uint64_t count = histogram[value];

        if (count < minimum) {
            second = minimum;
            minimum = count;
            minimum_index = (uint8_t)value;
            multiplicity = 1u;
        } else if (count == minimum) {
            ++multiplicity;
        } else if (count < second) {
            second = count;
        }
    }

    if (second == UINT64_MAX) {
        second = minimum;
    }

    *minimum_value = minimum_index;
    *minimum_count = minimum;
    *second_minimum_count = second;
    *minimum_multiplicity = multiplicity;
}

void scenery_unknown_infection_result_init(
    scenery_unknown_infection_result *result
)
{
    if (result != NULL) {
        memset(result, 0, sizeof(*result));
    }
}

int scenery_unknown_infection_add_ciphertext(
    scenery_unknown_infection_result *result,
    const uint8_t ciphertext[SCENERY_BLOCK_SIZE]
)
{
    size_t sbox;

    if (result == NULL || ciphertext == NULL) {
        return -1;
    }

    for (sbox = 0u; sbox < SCENERY_UNKNOWN_INFECTION_SBOXES; ++sbox) {
        const uint8_t value = scenery_last_round_public_word(
            ciphertext,
            (uint8_t)sbox
        );
        ++result->histogram[sbox][value];
    }
    ++result->sample_count;
    return 0;
}

int scenery_unknown_infection_identify_fault(
    scenery_unknown_infection_result *result
)
{
    size_t sbox;

    if (result == NULL || result->sample_count == 0u) {
        return -1;
    }

    result->success = 0;
    result->best_sei = -DBL_MAX;
    result->second_best_sei = -DBL_MAX;
    result->best_candidate_count = 0u;
    result->detected_sbox = 0u;
    result->detected_public_minimum = 0u;
    result->sei_gap = 0.0;

    for (sbox = 0u; sbox < SCENERY_UNKNOWN_INFECTION_SBOXES; ++sbox) {
        const double score = squared_euclidean_imbalance(
            result->histogram[sbox],
            result->sample_count
        );

        result->lane_sei[sbox] = score;
        characterize_minimum(
            result->histogram[sbox],
            &result->minimum_value[sbox],
            &result->minimum_count[sbox],
            &result->second_minimum_count[sbox],
            &result->minimum_multiplicity[sbox]
        );

        if (score > result->best_sei) {
            result->second_best_sei = result->best_sei;
            result->best_sei = score;
            result->detected_sbox = (uint8_t)sbox;
            result->best_candidate_count = 1u;
        } else if (score == result->best_sei) {
            ++result->best_candidate_count;
        } else if (score > result->second_best_sei) {
            result->second_best_sei = score;
        }
    }

    for (sbox = 0u; sbox < SCENERY_UNKNOWN_INFECTION_SBOXES; ++sbox) {
        size_t rank = 1u;
        size_t other;

        for (other = 0u;
             other < SCENERY_UNKNOWN_INFECTION_SBOXES;
             ++other) {
            if (result->lane_sei[other] > result->lane_sei[sbox]) {
                ++rank;
            }
        }
        result->lane_rank[sbox] = rank;
    }

    if (result->best_candidate_count != 1u) {
        return 1;
    }

    result->detected_public_minimum =
        result->minimum_value[result->detected_sbox];
    if (result->minimum_multiplicity[result->detected_sbox] != 1u) {
        return 2;
    }

    result->sei_gap = result->best_sei - result->second_best_sei;
    result->success = 1;
    return 0;
}

uint8_t scenery_unknown_infection_key_word_candidate(
    uint8_t public_minimum,
    uint8_t delta_candidate
)
{
    return (uint8_t)((public_minimum ^ delta_candidate) & 0x0Fu);
}

/* ------------------------------------------------------------------------- */
/* Algorithm 4 / Step 2: exact 2^20 active-key SEI ranking.                 */
/* ------------------------------------------------------------------------- */

typedef struct scenery_unknown_infection_precomputed_sample {
    uint32_t active_word_tuple;
    uint8_t right_target_word;
} scenery_unknown_infection_precomputed_sample;

static uint32_t unknown_infection_load32_be(const uint8_t input[4])
{
    return ((uint32_t)input[0] << 24) |
           ((uint32_t)input[1] << 16) |
           ((uint32_t)input[2] <<  8) |
           ((uint32_t)input[3]);
}

static unsigned int unknown_infection_popcount4(uint8_t value)
{
    unsigned int count = 0u;

    value &= 0x0Fu;
    while (value != 0u) {
        count += (unsigned int)(value & 1u);
        value = (uint8_t)(value >> 1);
    }
    return count;
}

static unsigned int unknown_infection_parity4(uint8_t value)
{
    value ^= (uint8_t)(value >> 2);
    value ^= (uint8_t)(value >> 1);
    return (unsigned int)(value & 1u);
}

static int64_t unknown_infection_character(uint8_t mask, uint8_t value)
{
    return unknown_infection_parity4((uint8_t)(mask & value)) == 0u
        ? INT64_C(1)
        : -INT64_C(1);
}

/* Same MixColumns role decomposition used by Algorithm-2 partial inversion. */
static uint8_t unknown_infection_role_contribution(
    uint8_t role,
    uint8_t substituted
)
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

/* Unnormalized XOR Walsh-Hadamard transform; applying it twice gives n*x. */
static void unknown_infection_fwht_i64(int64_t *values, size_t count)
{
    size_t half;

    for (half = 1u; half < count; half <<= 1u) {
        const size_t block = half << 1u;
        size_t base;

        for (base = 0u; base < count; base += block) {
            size_t offset;

            for (offset = 0u; offset < half; ++offset) {
                const int64_t first = values[base + offset];
                const int64_t second = values[base + half + offset];

                values[base + offset] = first + second;
                values[base + half + offset] = first - second;
            }
        }
    }
}

static int unknown_infection_precompute_samples(
    const uint8_t *ciphertexts,
    size_t sample_count,
    uint8_t target_sbox,
    const uint8_t active_sboxes[SCENERY_UNKNOWN_ACTIVE_WORDS],
    scenery_unknown_infection_precomputed_sample *samples
)
{
    size_t sample;

    for (sample = 0u; sample < sample_count; ++sample) {
        const uint8_t *ciphertext =
            ciphertexts + sample * SCENERY_BLOCK_SIZE;
        uint32_t tuple = UINT32_C(0);
        size_t role;

        for (role = 0u; role < SCENERY_UNKNOWN_ACTIVE_WORDS; ++role) {
            const uint8_t public_word = scenery_last_round_public_word(
                ciphertext,
                active_sboxes[role]
            );
            tuple |= (uint32_t)public_word << (4u * role);
        }

        samples[sample].active_word_tuple = tuple;
        samples[sample].right_target_word = scenery_extract_sbox_word(
            unknown_infection_load32_be(ciphertext + 4u),
            target_sbox
        );
    }
    return 0;
}

static void unknown_infection_build_kernel_spectrum(
    uint8_t walsh_mask,
    int64_t transformed_role_kernel[SCENERY_UNKNOWN_ACTIVE_WORDS]
                                   [SCENERY_UNKNOWN_INFECTION_DOMAIN]
)
{
    size_t role;

    for (role = 0u; role < SCENERY_UNKNOWN_ACTIVE_WORDS; ++role) {
        size_t input;

        for (input = 0u; input < SCENERY_UNKNOWN_INFECTION_DOMAIN; ++input) {
            const uint8_t substituted = scenery_sbox_correct((uint8_t)input);
            const uint8_t contribution =
                unknown_infection_role_contribution(
                    (uint8_t)role,
                    substituted
                );
            transformed_role_kernel[role][input] =
                unknown_infection_character(walsh_mask, contribution);
        }
        unknown_infection_fwht_i64(
            transformed_role_kernel[role],
            SCENERY_UNKNOWN_INFECTION_DOMAIN
        );
    }
}

static int unknown_infection_accumulate_mask_scores(
    const scenery_unknown_infection_precomputed_sample *samples,
    size_t sample_count,
    uint8_t walsh_mask,
    int64_t *spectrum,
    uint64_t *score_numerators
)
{
    int64_t transformed_role_kernel[SCENERY_UNKNOWN_ACTIVE_WORDS]
                                       [SCENERY_UNKNOWN_INFECTION_DOMAIN];
    const size_t candidate_count =
        (size_t)SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES;
    size_t sample;
    size_t frequency;

    memset(spectrum, 0, candidate_count * sizeof(*spectrum));
    for (sample = 0u; sample < sample_count; ++sample) {
        const int64_t sign = unknown_infection_character(
            walsh_mask,
            samples[sample].right_target_word
        );
        spectrum[samples[sample].active_word_tuple] += sign;
    }

    unknown_infection_fwht_i64(spectrum, candidate_count);
    unknown_infection_build_kernel_spectrum(
        walsh_mask,
        transformed_role_kernel
    );

    for (frequency = 0u; frequency < candidate_count; ++frequency) {
        int64_t kernel_spectrum = INT64_C(1);
        size_t role;

        for (role = 0u; role < SCENERY_UNKNOWN_ACTIVE_WORDS; ++role) {
            const size_t role_frequency =
                (frequency >> (4u * role)) & 0x0Fu;
            kernel_spectrum *=
                transformed_role_kernel[role][role_frequency];
        }
        spectrum[frequency] *= kernel_spectrum;
    }

    /* The same transform is the inverse up to division by 2^20. */
    unknown_infection_fwht_i64(spectrum, candidate_count);
    for (frequency = 0u; frequency < candidate_count; ++frequency) {
        int64_t coefficient;
        uint64_t magnitude;

        if ((spectrum[frequency] % (int64_t)candidate_count) != 0) {
            return -3;
        }
        coefficient = spectrum[frequency] / (int64_t)candidate_count;
        magnitude = coefficient < 0
            ? (uint64_t)(-coefficient)
            : (uint64_t)coefficient;
        score_numerators[frequency] += magnitude * magnitude;
    }
    return 0;
}

static void unknown_infection_summarize_top_candidates(
    const uint64_t *score_numerators,
    scenery_unknown_infection_active_candidate *top_candidates,
    size_t top_candidate_capacity,
    scenery_unknown_infection_partial_result *result
)
{
    const size_t candidate_count =
        (size_t)SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES;
    uint8_t first_words[SCENERY_UNKNOWN_ACTIVE_WORDS] = { 0u, 0u, 0u, 0u, 0u };
    uint8_t differences[SCENERY_UNKNOWN_ACTIVE_WORDS] = { 0u, 0u, 0u, 0u, 0u };
    int have_first = 0;
    size_t candidate;

    result->top_score_numerator = 0u;
    for (candidate = 0u; candidate < candidate_count; ++candidate) {
        if (score_numerators[candidate] > result->top_score_numerator) {
            result->top_score_numerator = score_numerators[candidate];
        }
    }

    result->second_score_numerator = 0u;
    for (candidate = 0u; candidate < candidate_count; ++candidate) {
        const uint64_t score = score_numerators[candidate];

        if (score < result->top_score_numerator &&
            score > result->second_score_numerator) {
            result->second_score_numerator = score;
        }
    }

    for (candidate = 0u; candidate < candidate_count; ++candidate) {
        if (score_numerators[candidate] == result->top_score_numerator) {
            uint8_t words[SCENERY_UNKNOWN_ACTIVE_WORDS];
            size_t role;

            scenery_unknown_unpack_active_words((uint32_t)candidate, words);
            if (!have_first) {
                memcpy(first_words, words, sizeof(first_words));
                have_first = 1;
            } else {
                for (role = 0u; role < SCENERY_UNKNOWN_ACTIVE_WORDS; ++role) {
                    differences[role] |=
                        (uint8_t)(first_words[role] ^ words[role]);
                }
            }

            if (result->stored_top_candidate_count < top_candidate_capacity) {
                scenery_unknown_infection_active_candidate *stored =
                    &top_candidates[result->stored_top_candidate_count];
                stored->packed_words = (uint32_t)candidate;
                stored->score_numerator = score_numerators[candidate];
                stored->sei = scenery_unknown_infection_score_to_sei(
                    score_numerators[candidate],
                    result->sample_count
                );
                stored->rank = 1u;
                ++result->stored_top_candidate_count;
            }
            ++result->top_candidate_count;
        }
    }

    result->recovered_active_bits = 0u;
    if (have_first) {
        size_t role;

        for (role = 0u; role < SCENERY_UNKNOWN_ACTIVE_WORDS; ++role) {
            result->known_bit_masks[role] =
                (uint8_t)((~differences[role]) & 0x0Fu);
            result->known_bit_values[role] =
                (uint8_t)(first_words[role] & result->known_bit_masks[role]);
            result->recovered_active_bits += unknown_infection_popcount4(
                result->known_bit_masks[role]
            );
        }
    }

    /* Role B is the target S-box word and determines delta with Step 1. */
    if (result->known_bit_masks[1] == 0x0Fu) {
        result->recovered_delta = (uint8_t)(
            result->public_minimum ^ result->known_bit_values[1]
        );
        result->delta_recovered = 1;
    }

    result->top_sei = scenery_unknown_infection_score_to_sei(
        result->top_score_numerator,
        result->sample_count
    );
    result->second_sei = scenery_unknown_infection_score_to_sei(
        result->second_score_numerator,
        result->sample_count
    );
    result->sei_gap = result->top_sei - result->second_sei;
    result->success = result->top_candidate_count > 0u &&
                      result->top_score_numerator >
                          result->second_score_numerator &&
                      result->delta_recovered;
}

double scenery_unknown_infection_score_to_sei(
    uint64_t score_numerator,
    size_t sample_count
)
{
    const double count = (double)sample_count;

    if (sample_count == 0u) {
        return 0.0;
    }
    return (double)score_numerator /
           ((double)SCENERY_UNKNOWN_INFECTION_DOMAIN * count * count);
}

int scenery_unknown_infection_rank_active_key_candidates(
    const uint8_t *ciphertexts,
    size_t sample_count,
    uint8_t target_sbox,
    uint8_t public_minimum,
    uint64_t *score_numerators,
    size_t score_capacity,
    scenery_unknown_infection_active_candidate *top_candidates,
    size_t top_candidate_capacity,
    scenery_unknown_infection_partial_result *result
)
{
    scenery_unknown_infection_precomputed_sample *samples;
    int64_t *spectrum;
    uint8_t active_sboxes[SCENERY_UNKNOWN_ACTIVE_WORDS];
    uint8_t walsh_mask;
    int status = 0;

    if (ciphertexts == NULL || sample_count == 0u ||
        sample_count > (size_t)SCENERY_UNKNOWN_INFECTION_MAX_SAMPLES ||
        target_sbox >= SCENERY_UNKNOWN_INFECTION_SBOXES ||
        public_minimum >= SCENERY_UNKNOWN_INFECTION_DOMAIN ||
        score_numerators == NULL ||
        score_capacity <
            (size_t)SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES ||
        result == NULL ||
        (top_candidate_capacity > 0u && top_candidates == NULL) ||
        scenery_unknown_active_sboxes(target_sbox, active_sboxes) != 0) {
        return -1;
    }

    memset(result, 0, sizeof(*result));
    result->sample_count = sample_count;
    result->target_sbox = target_sbox;
    result->public_minimum = public_minimum;
    result->tested_candidates =
        SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES;
    memcpy(result->active_sboxes, active_sboxes, sizeof(active_sboxes));
    memset(
        score_numerators,
        0,
        (size_t)SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES *
            sizeof(*score_numerators)
    );

    samples = (scenery_unknown_infection_precomputed_sample *)malloc(
        sample_count * sizeof(*samples)
    );
    spectrum = (int64_t *)malloc(
        (size_t)SCENERY_UNKNOWN_INFECTION_ACTIVE_CANDIDATES *
            sizeof(*spectrum)
    );
    if (samples == NULL || spectrum == NULL) {
        free(samples);
        free(spectrum);
        return -2;
    }

    (void)unknown_infection_precompute_samples(
        ciphertexts,
        sample_count,
        target_sbox,
        active_sboxes,
        samples
    );

    for (walsh_mask = 1u;
         walsh_mask < SCENERY_UNKNOWN_INFECTION_DOMAIN;
         ++walsh_mask) {
        status = unknown_infection_accumulate_mask_scores(
            samples,
            sample_count,
            walsh_mask,
            spectrum,
            score_numerators
        );
        if (status != 0) {
            break;
        }
        ++result->walsh_masks_evaluated;
    }

    free(samples);
    free(spectrum);
    if (status != 0) {
        return status;
    }

    unknown_infection_summarize_top_candidates(
        score_numerators,
        top_candidates,
        top_candidate_capacity,
        result
    );
    return 0;
}

/* ------------------------------------------------------------------------- */
/* Algorithm 4 / Step 3: structural-equivalence audit of rank-1 candidates. */
/* ------------------------------------------------------------------------- */

static uint64_t unknown_infection_direct_score_numerator(
    const uint8_t *sequence,
    size_t sample_count,
    uint64_t histogram[SCENERY_UNKNOWN_INFECTION_DOMAIN]
)
{
    uint64_t sum_squares = UINT64_C(0);
    size_t sample;
    size_t value;

    memset(
        histogram,
        0,
        SCENERY_UNKNOWN_INFECTION_DOMAIN * sizeof(*histogram)
    );
    for (sample = 0u; sample < sample_count; ++sample) {
        ++histogram[sequence[sample] & 0x0Fu];
    }
    for (value = 0u; value < SCENERY_UNKNOWN_INFECTION_DOMAIN; ++value) {
        sum_squares += histogram[value] * histogram[value];
    }
    return UINT64_C(16) * sum_squares -
           (uint64_t)sample_count * (uint64_t)sample_count;
}

static size_t unknown_infection_count_exact_sequences(
    const uint8_t *sequences,
    size_t sample_count,
    size_t candidate_count
)
{
    size_t unique = 0u;
    size_t candidate;

    for (candidate = 0u; candidate < candidate_count; ++candidate) {
        size_t prior;
        int seen = 0;

        for (prior = 0u; prior < candidate; ++prior) {
            if (memcmp(
                    sequences + candidate * sample_count,
                    sequences + prior * sample_count,
                    sample_count) == 0) {
                seen = 1;
                break;
            }
        }
        if (!seen) {
            ++unique;
        }
    }
    return unique;
}

static size_t unknown_infection_count_unique_scores(
    const uint64_t *scores,
    size_t candidate_count
)
{
    size_t unique = 0u;
    size_t candidate;

    for (candidate = 0u; candidate < candidate_count; ++candidate) {
        size_t prior;
        int seen = 0;

        for (prior = 0u; prior < candidate; ++prior) {
            if (scores[prior] == scores[candidate]) {
                seen = 1;
                break;
            }
        }
        if (!seen) {
            ++unique;
        }
    }
    return unique;
}

static size_t unknown_infection_count_xor_classes(
    uint8_t relation[SCENERY_UNKNOWN_INFECTION_EQUIVALENCE_MAX]
                          [SCENERY_UNKNOWN_INFECTION_EQUIVALENCE_MAX],
    size_t candidate_count
)
{
    uint8_t assigned[SCENERY_UNKNOWN_INFECTION_EQUIVALENCE_MAX] = { 0u };
    size_t classes = 0u;
    size_t candidate;

    for (candidate = 0u; candidate < candidate_count; ++candidate) {
        size_t other;

        if (assigned[candidate] != 0u) {
            continue;
        }
        ++classes;
        assigned[candidate] = 1u;
        for (other = candidate + 1u; other < candidate_count; ++other) {
            if (relation[candidate][other] != 0u) {
                assigned[other] = 1u;
            }
        }
    }
    return classes;
}

int scenery_unknown_infection_audit_candidate_equivalence(
    const uint8_t *ciphertexts,
    size_t sample_count,
    uint8_t target_sbox,
    const uint32_t *packed_candidates,
    size_t candidate_count,
    scenery_unknown_infection_equivalence_result *result
)
{
    uint8_t *sequences;
    uint64_t histograms[SCENERY_UNKNOWN_INFECTION_EQUIVALENCE_MAX]
                       [SCENERY_UNKNOWN_INFECTION_DOMAIN];
    size_t candidate;

    if (ciphertexts == NULL || sample_count == 0u ||
        target_sbox >= SCENERY_UNKNOWN_INFECTION_SBOXES ||
        packed_candidates == NULL || result == NULL ||
        candidate_count == 0u ||
        candidate_count > SCENERY_UNKNOWN_INFECTION_EQUIVALENCE_MAX ||
        sample_count > SIZE_MAX / candidate_count) {
        return -1;
    }

    memset(result, 0, sizeof(*result));
    result->sample_count = sample_count;
    result->target_sbox = target_sbox;
    result->candidate_count = candidate_count;
    result->all_pairs_xor_equivalent = 1;

    sequences = (uint8_t *)malloc(candidate_count * sample_count);
    if (sequences == NULL) {
        return -2;
    }

    for (candidate = 0u; candidate < candidate_count; ++candidate) {
        size_t sample;
        uint8_t *sequence = sequences + candidate * sample_count;

        for (sample = 0u; sample < sample_count; ++sample) {
            sequence[sample] = scenery_unknown_partial_decrypt_previous_word(
                ciphertexts + sample * SCENERY_BLOCK_SIZE,
                target_sbox,
                packed_candidates[candidate]
            );
        }
        result->score_numerators[candidate] =
            unknown_infection_direct_score_numerator(
                sequence,
                sample_count,
                histograms[candidate]
            );
    }

    for (candidate = 0u; candidate < candidate_count; ++candidate) {
        size_t other;

        for (other = 0u; other < candidate_count; ++other) {
            const uint8_t *first = sequences + candidate * sample_count;
            const uint8_t *second = sequences + other * sample_count;
            const uint8_t constant = (uint8_t)(first[0] ^ second[0]);
            size_t sample;
            size_t value;
            int constant_valid = 1;
            int histogram_equal = 1;

            for (sample = 1u; sample < sample_count; ++sample) {
                if ((uint8_t)(first[sample] ^ second[sample]) != constant) {
                    constant_valid = 0;
                    break;
                }
            }
            result->constant_xor[candidate][other] = constant;
            result->constant_xor_valid[candidate][other] =
                (uint8_t)(constant_valid ? 1u : 0u);

            if (constant_valid) {
                for (value = 0u;
                     value < SCENERY_UNKNOWN_INFECTION_DOMAIN;
                     ++value) {
                    if (histograms[candidate][value] !=
                        histograms[other][value ^ constant]) {
                        histogram_equal = 0;
                        break;
                    }
                }
            } else {
                histogram_equal = 0;
                result->all_pairs_xor_equivalent = 0;
            }
            result->histogram_permutation_equal[candidate][other] =
                (uint8_t)(histogram_equal ? 1u : 0u);
        }
    }

    result->unique_exact_sequences =
        unknown_infection_count_exact_sequences(
            sequences,
            sample_count,
            candidate_count
        );
    result->unique_score_count = unknown_infection_count_unique_scores(
        result->score_numerators,
        candidate_count
    );
    result->xor_equivalence_classes = unknown_infection_count_xor_classes(
        result->constant_xor_valid,
        candidate_count
    );
    result->success = 1;

    free(sequences);
    return 0;
}
