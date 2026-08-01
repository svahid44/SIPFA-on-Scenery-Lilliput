#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "attack_common.h"
#include "attack_round.h"
#include "cipher.h"
#include "persistent_fault.h"
#include "reference_trace.h"

#define PHASE2_TARGET_INEFFECTIVE 4000U
#define PHASE2_MAX_QUERIES 30000U

static int fail(const char *message)
{
    fprintf(stderr, "FAIL: %s\n", message);
    return 1;
}

static uint64_t splitmix64_next(uint64_t *state)
{
    uint64_t z;

    *state += UINT64_C(0x9E3779B97F4A7C15);
    z = *state;
    z = (z ^ (z >> 30)) * UINT64_C(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)) * UINT64_C(0x94D049BB133111EB);
    return z ^ (z >> 31);
}

static void random_block(uint64_t *state, uint8_t block[BLOCK_BYTES])
{
    for (size_t offset = 0U; offset < BLOCK_BYTES; offset += 8U) {
        const uint64_t word = splitmix64_next(state);
        for (size_t byte = 0U; byte < 8U; ++byte) {
            block[offset + byte] = (uint8_t)(word >> (8U * byte));
        }
    }
}

static size_t trace_fault_hits(
    const lilliput_reference_trace *trace,
    uint8_t delta
)
{
    size_t hits = 0U;

    for (size_t round = 0U; round < ROUNDS; ++round) {
        for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
            if (trace->sbox_input[round][lane] == delta) {
                ++hits;
            }
        }
    }
    return hits;
}

static int verify_structural_mapping(void)
{
    uint8_t key[KEY_BYTES];
    uint8_t tweak[TWEAK_BYTES];
    uint64_t prng_state = UINT64_C(0x5048415345324d41);

    for (size_t i = 0U; i < KEY_BYTES; ++i) {
        key[i] = (uint8_t)i;
        tweak[i] = (uint8_t)(0xf0U ^ (uint8_t)i);
    }

    for (size_t trial = 0U; trial < 512U; ++trial) {
        uint8_t plaintext[BLOCK_BYTES];
        uint8_t ciphertext[BLOCK_BYTES];
        uint8_t reference_ciphertext[BLOCK_BYTES];
        uint8_t peeled[BLOCK_BYTES];
        uint8_t penultimate_x[ROUND_TWEAKEY_BYTES];
        lilliput_reference_trace trace;

        random_block(&prng_state, plaintext);
        lilliput_tbc_encrypt(key, tweak, plaintext, ciphertext);
        if (lilliput_reference_encrypt_trace(
                key, tweak, plaintext, reference_ciphertext, &trace) != 0) {
            return fail("reference trace failed");
        }
        if (memcmp(ciphertext, reference_ciphertext, BLOCK_BYTES) != 0) {
            return fail("trace encryption disagrees with reference encryption");
        }

        /* Final round: x_32 is directly visible in C[0..7]. */
        if (memcmp(
                ciphertext,
                trace.state_before_round[ROUNDS - 1U],
                ROUND_TWEAKEY_BYTES) != 0) {
            return fail("C[0..7] is not paper x_32 for the final round");
        }
        for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
            const uint8_t mapped_y = (uint8_t)(
                ciphertext[lane] ^
                trace.round_tweakey[ROUNDS - 1U][lane]
            );
            if (mapped_y != trace.sbox_input[ROUNDS - 1U][lane]) {
                return fail("final-round y_32 = x_32 XOR RTK[31] mapping failed");
            }
        }

        /* Algorithm 1/3 partial decryption: remove paper round n. */
        lilliput_attack_peel_final_round(
            ciphertext,
            trace.round_tweakey[ROUNDS - 1U],
            peeled
        );
        if (memcmp(
                peeled,
                trace.state_before_round[ROUNDS - 1U],
                BLOCK_BYTES) != 0) {
            return fail("peeling RTK[31] did not recover the input of round 32");
        }

        /* Undo round-31 permutation to recover paper x_31. */
        lilliput_attack_extract_penultimate_inputs(peeled, penultimate_x);
        if (memcmp(
                penultimate_x,
                trace.state_before_round[ROUNDS - 2U],
                ROUND_TWEAKEY_BYTES) != 0) {
            return fail("penultimate extraction did not recover paper x_31");
        }
        for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
            const uint8_t mapped_y = (uint8_t)(
                penultimate_x[lane] ^
                trace.round_tweakey[ROUNDS - 2U][lane]
            );
            if (mapped_y != trace.sbox_input[ROUNDS - 2U][lane]) {
                return fail("penultimate y_31 = x_31 XOR RTK[30] mapping failed");
            }
        }
    }

    return 0;
}

static int verify_ineffective_event_mapping(void)
{
    uint8_t key[KEY_BYTES];
    uint8_t tweak[TWEAK_BYTES];
    const uint8_t delta = UINT8_C(0x5a);
    const uint8_t faulty_output =
        (uint8_t)(lilliput_sbox_correct(delta) ^ UINT8_C(0x80));
    uint8_t rtk31[ROUND_TWEAKEY_BYTES];
    uint8_t rtk30[ROUND_TWEAKEY_BYTES];
    uint64_t prng_state = UINT64_C(456);
    uint64_t final_histogram
        [ROUND_TWEAKEY_BYTES][LILLIPUT_SBOX_DOMAIN];
    uint64_t penultimate_histogram
        [ROUND_TWEAKEY_BYTES][LILLIPUT_SBOX_DOMAIN];
    size_t ineffective = 0U;
    size_t queries = 0U;
    double expected_rate = 1.0;

    memset(final_histogram, 0, sizeof(final_histogram));
    memset(penultimate_histogram, 0, sizeof(penultimate_histogram));

    for (size_t i = 0U; i < KEY_BYTES; ++i) {
        key[i] = (uint8_t)i;
        tweak[i] = (uint8_t)i;
    }

    /* Ground truth is validation-only and is never exposed to attack code. */
    {
        uint8_t dummy_plaintext[BLOCK_BYTES] = {0};
        uint8_t dummy_ciphertext[BLOCK_BYTES];
        lilliput_reference_trace trace;

        if (lilliput_reference_encrypt_trace(
                key, tweak, dummy_plaintext, dummy_ciphertext, &trace) != 0) {
            return fail("could not derive validation RTKs");
        }
        memcpy(rtk31, trace.round_tweakey[ROUNDS - 1U], sizeof(rtk31));
        memcpy(rtk30, trace.round_tweakey[ROUNDS - 2U], sizeof(rtk30));
    }

    lilliput_fault_reset();
    if (lilliput_fault_inject(delta, faulty_output) != 0) {
        return fail("could not inject the Phase-2 persistent fault");
    }

    while ((ineffective < PHASE2_TARGET_INEFFECTIVE) &&
           (queries < PHASE2_MAX_QUERIES)) {
        uint8_t plaintext[BLOCK_BYTES];
        uint8_t correct_ciphertext[BLOCK_BYTES];
        uint8_t faulty_ciphertext[BLOCK_BYTES];
        uint8_t traced_ciphertext[BLOCK_BYTES];
        lilliput_reference_trace trace;
        size_t hits;
        int is_ineffective;

        random_block(&prng_state, plaintext);
        lilliput_tbc_encrypt(key, tweak, plaintext, correct_ciphertext);
        lilliput_tbc_encrypt_faulty(key, tweak, plaintext, faulty_ciphertext);
        if (lilliput_reference_encrypt_trace(
                key, tweak, plaintext, traced_ciphertext, &trace) != 0) {
            return fail("reference trace failed during ineffective-event test");
        }
        if (memcmp(correct_ciphertext, traced_ciphertext, BLOCK_BYTES) != 0) {
            return fail("trace ciphertext mismatch during ineffective-event test");
        }

        ++queries;
        hits = trace_fault_hits(&trace, delta);
        is_ineffective =
            (memcmp(correct_ciphertext, faulty_ciphertext, BLOCK_BYTES) == 0);

        /* This is the paper's persistent-fault ineffective-event condition. */
        if ((is_ineffective != 0) != (hits == 0U)) {
            return fail("C_correct == C_faulty is not equivalent to zero S-box hits");
        }

        if (is_ineffective != 0) {
            uint8_t peeled[BLOCK_BYTES];
            uint8_t penultimate_x[ROUND_TWEAKEY_BYTES];

            ++ineffective;
            lilliput_attack_peel_final_round(
                correct_ciphertext,
                rtk31,
                peeled
            );
            lilliput_attack_extract_penultimate_inputs(
                peeled,
                penultimate_x
            );

            for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
                if (trace.sbox_input[ROUNDS - 1U][lane] == delta) {
                    return fail("ineffective sample contains delta in final round");
                }
                if (trace.sbox_input[ROUNDS - 2U][lane] == delta) {
                    return fail("ineffective sample contains delta in penultimate round");
                }
                ++final_histogram[lane][correct_ciphertext[lane]];
                ++penultimate_histogram[lane][penultimate_x[lane]];
            }
        }
    }

    if (ineffective != PHASE2_TARGET_INEFFECTIVE) {
        return fail("insufficient ineffective samples for Phase-2 mapping test");
    }

    /* Article Eq. (7): (1 - 2^-8)^(8*32) for one shared S-box. */
    for (size_t call = 0U;
         call < (size_t)ROUNDS * ROUND_TWEAKEY_BYTES;
         ++call) {
        expected_rate *= 255.0 / 256.0;
    }
    {
        const double observed_rate = (double)ineffective / (double)queries;
        double difference = observed_rate - expected_rate;
        if (difference < 0.0) {
            difference = -difference;
        }
        if (difference > 0.02) {
            return fail("observed ineffective rate disagrees with Article Eq. (7)");
        }
        printf(
            "Phase-2 ineffective rate: observed=%.6f expected=%.6f queries=%zu\n",
            observed_rate,
            expected_rate,
            queries
        );
    }

    for (size_t lane = 0U; lane < ROUND_TWEAKEY_BYTES; ++lane) {
        uint8_t missing[LILLIPUT_SBOX_DOMAIN];
        size_t missing_count = lilliput_histogram_missing_values(
            final_histogram[lane], missing
        );

        if ((missing_count != 1U) ||
            (missing[0] != (uint8_t)(delta ^ rtk31[lane]))) {
            return fail("final-round excluded value does not match delta XOR RTK[31]");
        }

        missing_count = lilliput_histogram_missing_values(
            penultimate_histogram[lane], missing
        );
        if ((missing_count != 1U) ||
            (missing[0] != (uint8_t)(delta ^ rtk30[lane]))) {
            return fail("penultimate excluded value does not match delta XOR RTK[30]");
        }
    }

    lilliput_fault_reset();
    return 0;
}

int main(void)
{
    if (verify_structural_mapping() != 0) {
        return 1;
    }
    if (verify_ineffective_event_mapping() != 0) {
        return 1;
    }

    puts("PASS: Phase 2 formally maps Lilliput rounds to the SIPFA article model.");
    return 0;
}
