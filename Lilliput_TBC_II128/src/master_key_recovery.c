#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "constants.h"
#include "master_key_recovery.h"
#include "multiplications.h"
#include "parameters.h"

#define MASTER_KEY_BITS (KEY_BYTES * 8U)
#define EQUATION_COUNT   (2U * ROUND_TWEAKEY_BYTES * 8U)
#define COEFFICIENT_WORDS 2U

#if KEY_LENGTH_BITS != 128
#error "This recovery module is specialized to Lilliput-TBC-II-128."
#endif

#if ROUND_TWEAKEY_LENGTH_BITS != 64
#error "This recovery module expects 64-bit round tweakeys."
#endif

typedef void (*lane_transform)(
    const uint8_t input[LANE_BYTES],
    uint8_t output[LANE_BYTES]
);

typedef struct gf2_row {
    uint64_t coefficients[COEFFICIENT_WORDS];
    uint8_t rhs;
} gf2_row;

/*
 * Referencing all seven official multiplication helpers keeps this translation
 * unit warning-clean under -Werror; only indices 0..3 are used by II-128.
 */
static const lane_transform SCHEDULE_TRANSFORMS[7] = {
    _multiply_M,
    _multiply_M2,
    _multiply_M3,
    _multiply_M4,
    _multiply_MR,
    _multiply_MR2,
    _multiply_MR3
};

static uint8_t byte_bit(
    const uint8_t *bytes,
    size_t bit_index
)
{
    return (uint8_t)((bytes[bit_index / 8U] >> (bit_index % 8U)) & 1U);
}

static void set_byte_bit(
    uint8_t *bytes,
    size_t bit_index,
    uint8_t value
)
{
    const uint8_t mask = (uint8_t)(1U << (bit_index % 8U));

    if (value != 0U) {
        bytes[bit_index / 8U] |= mask;
    } else {
        bytes[bit_index / 8U] &= (uint8_t)~mask;
    }
}

static uint8_t row_bit(const gf2_row *row, size_t column)
{
    return (uint8_t)(
        (row->coefficients[column / 64U] >> (column % 64U)) & UINT64_C(1)
    );
}

static void row_set_bit(gf2_row *row, size_t column)
{
    row->coefficients[column / 64U] |=
        UINT64_C(1) << (column % 64U);
}

static void row_xor(gf2_row *destination, const gf2_row *source)
{
    for (size_t word = 0U; word < COEFFICIENT_WORDS; ++word) {
        destination->coefficients[word] ^= source->coefficients[word];
    }
    destination->rhs ^= source->rhs;
}

static int row_has_no_coefficients(const gf2_row *row)
{
    return (row->coefficients[0] == UINT64_C(0)) &&
           (row->coefficients[1] == UINT64_C(0));
}

static void apply_power(
    const uint8_t input[LANE_BYTES],
    size_t exponent,
    lane_transform transform,
    uint8_t output[LANE_BYTES]
)
{
    uint8_t current[LANE_BYTES];
    uint8_t next[LANE_BYTES];

    memcpy(current, input, LANE_BYTES);
    for (size_t step = 0U; step < exponent; ++step) {
        transform(current, next);
        memcpy(current, next, LANE_BYTES);
    }
    memcpy(output, current, LANE_BYTES);
}

static void compute_public_part(
    const uint8_t tweak[TWEAK_BYTES],
    size_t round_index,
    uint8_t public_part[ROUND_TWEAKEY_BYTES]
)
{
    uint8_t transformed_t0[LANE_BYTES];
    uint8_t transformed_t1[LANE_BYTES];

    apply_power(tweak, round_index, SCHEDULE_TRANSFORMS[0], transformed_t0);
    apply_power(tweak + LANE_BYTES,
                round_index,
                SCHEDULE_TRANSFORMS[1],
                transformed_t1);

    for (size_t index = 0U; index < ROUND_TWEAKEY_BYTES; ++index) {
        public_part[index] =
            (uint8_t)(transformed_t0[index] ^ transformed_t1[index]);
    }
    public_part[0] ^= (uint8_t)round_index;
}

static void compute_key_part(
    const uint8_t key[KEY_BYTES],
    size_t round_index,
    uint8_t key_part[ROUND_TWEAKEY_BYTES]
)
{
    uint8_t transformed_k0[LANE_BYTES];
    uint8_t transformed_k1[LANE_BYTES];

    apply_power(key, round_index, SCHEDULE_TRANSFORMS[2], transformed_k0);
    apply_power(key + LANE_BYTES,
                round_index,
                SCHEDULE_TRANSFORMS[3],
                transformed_k1);

    for (size_t index = 0U; index < ROUND_TWEAKEY_BYTES; ++index) {
        key_part[index] =
            (uint8_t)(transformed_k0[index] ^ transformed_k1[index]);
    }
}

static void compute_round_tweakey_from_components(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    size_t round_index,
    uint8_t round_tweakey[ROUND_TWEAKEY_BYTES]
)
{
    uint8_t public_part[ROUND_TWEAKEY_BYTES];
    uint8_t key_part[ROUND_TWEAKEY_BYTES];

    compute_public_part(tweak, round_index, public_part);
    compute_key_part(key, round_index, key_part);

    for (size_t index = 0U; index < ROUND_TWEAKEY_BYTES; ++index) {
        round_tweakey[index] = (uint8_t)(public_part[index] ^ key_part[index]);
    }
}

static void build_equation_system(
    const uint8_t tweak[TWEAK_BYTES],
    const uint8_t rtk30[ROUND_TWEAKEY_BYTES],
    const uint8_t rtk31[ROUND_TWEAKEY_BYTES],
    gf2_row rows[EQUATION_COUNT]
)
{
    uint8_t public30[ROUND_TWEAKEY_BYTES];
    uint8_t public31[ROUND_TWEAKEY_BYTES];
    uint8_t target[EQUATION_COUNT / 8U];

    compute_public_part(tweak, (size_t)ROUNDS - 2U, public30);
    compute_public_part(tweak, (size_t)ROUNDS - 1U, public31);

    for (size_t index = 0U; index < ROUND_TWEAKEY_BYTES; ++index) {
        target[index] = (uint8_t)(rtk30[index] ^ public30[index]);
        target[ROUND_TWEAKEY_BYTES + index] =
            (uint8_t)(rtk31[index] ^ public31[index]);
    }

    for (size_t row = 0U; row < EQUATION_COUNT; ++row) {
        rows[row].coefficients[0] = UINT64_C(0);
        rows[row].coefficients[1] = UINT64_C(0);
        rows[row].rhs = byte_bit(target, row);
    }

    for (size_t column = 0U; column < MASTER_KEY_BITS; ++column) {
        uint8_t basis_key[KEY_BYTES] = {0};
        uint8_t contribution30[ROUND_TWEAKEY_BYTES];
        uint8_t contribution31[ROUND_TWEAKEY_BYTES];
        uint8_t output[EQUATION_COUNT / 8U];

        set_byte_bit(basis_key, column, 1U);
        compute_key_part(basis_key, (size_t)ROUNDS - 2U, contribution30);
        compute_key_part(basis_key, (size_t)ROUNDS - 1U, contribution31);

        memcpy(output, contribution30, ROUND_TWEAKEY_BYTES);
        memcpy(output + ROUND_TWEAKEY_BYTES,
               contribution31,
               ROUND_TWEAKEY_BYTES);

        for (size_t row = 0U; row < EQUATION_COUNT; ++row) {
            if (byte_bit(output, row) != 0U) {
                row_set_bit(&rows[row], column);
            }
        }
    }
}

static int solve_full_rank_system(
    gf2_row rows[EQUATION_COUNT],
    uint8_t solution[KEY_BYTES],
    size_t *rank_out,
    int *consistent_out
)
{
    size_t pivot_columns[MASTER_KEY_BITS];
    size_t rank = 0U;

    for (size_t column = 0U;
         (column < MASTER_KEY_BITS) && (rank < EQUATION_COUNT);
         ++column) {
        size_t pivot = rank;

        while ((pivot < EQUATION_COUNT) &&
               (row_bit(&rows[pivot], column) == 0U)) {
            ++pivot;
        }
        if (pivot == EQUATION_COUNT) {
            continue;
        }

        if (pivot != rank) {
            const gf2_row temporary = rows[rank];
            rows[rank] = rows[pivot];
            rows[pivot] = temporary;
        }

        for (size_t row = 0U; row < EQUATION_COUNT; ++row) {
            if ((row != rank) && (row_bit(&rows[row], column) != 0U)) {
                row_xor(&rows[row], &rows[rank]);
            }
        }

        pivot_columns[rank] = column;
        ++rank;
    }

    *rank_out = rank;
    *consistent_out = 1;

    for (size_t row = rank; row < EQUATION_COUNT; ++row) {
        if (row_has_no_coefficients(&rows[row]) && (rows[row].rhs != 0U)) {
            *consistent_out = 0;
            return -2;
        }
    }

    if (rank < MASTER_KEY_BITS) {
        return -3;
    }

    memset(solution, 0, KEY_BYTES);
    for (size_t row = 0U; row < rank; ++row) {
        set_byte_bit(solution, pivot_columns[row], rows[row].rhs);
    }
    return 0;
}

int lilliput_recover_master_key_from_rtk30_rtk31(
    const uint8_t public_tweak[TWEAK_BYTES],
    const uint8_t recovered_rtk30[ROUND_TWEAKEY_BYTES],
    const uint8_t recovered_rtk31[ROUND_TWEAKEY_BYTES],
    lilliput_master_key_recovery_result *result
)
{
    gf2_row rows[EQUATION_COUNT];
    int solve_status;

    if ((public_tweak == NULL) ||
        (recovered_rtk30 == NULL) ||
        (recovered_rtk31 == NULL) ||
        (result == NULL)) {
        return -1;
    }

    memset(result, 0, sizeof(*result));
    result->equation_count = EQUATION_COUNT;

    build_equation_system(
        public_tweak,
        recovered_rtk30,
        recovered_rtk31,
        rows
    );

    solve_status = solve_full_rank_system(
        rows,
        result->recovered_key,
        &result->rank,
        &result->consistent
    );
    if (solve_status != 0) {
        result->unique = 0;
        return solve_status;
    }
    result->unique = 1;

    compute_round_tweakey_from_components(
        result->recovered_key,
        public_tweak,
        (size_t)ROUNDS - 2U,
        result->recomputed_rtk30
    );
    compute_round_tweakey_from_components(
        result->recovered_key,
        public_tweak,
        (size_t)ROUNDS - 1U,
        result->recomputed_rtk31
    );

    result->schedule_verification_passed =
        (memcmp(result->recomputed_rtk30,
                recovered_rtk30,
                ROUND_TWEAKEY_BYTES) == 0) &&
        (memcmp(result->recomputed_rtk31,
                recovered_rtk31,
                ROUND_TWEAKEY_BYTES) == 0);

    if (result->schedule_verification_passed == 0) {
        return -4;
    }
    return 0;
}
