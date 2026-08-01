#ifndef PERSISTENT_FAULT_H
#define PERSISTENT_FAULT_H

#include <stdint.h>

#include "scenery.h"

#ifdef __cplusplus
extern "C" {
#endif

#define SCENERY_LOGICAL_SBOXES 8u
#define SCENERY_SBOX_DOMAIN    16u

/*
 * Persistent single-entry fault model for one logical 4-bit SCENERY S-box.
 *
 * SCENERY evaluates eight logical S-boxes in parallel in bitsliced form.
 * To match the original SIPFA-on-DES model, one logical S-box index and one
 * input value are modified. The modification persists across all rounds and
 * all later calls to scenery_encrypt_block_faulty() until reset.
 */

void scenery_fault_reset(void);

/*
 * Set S_faulty[sbox_index][input] = faulty_output.
 * Returns 0 on success and -1 for invalid parameters or if faulty_output is
 * equal to the correct S-box output.
 */
int scenery_fault_inject(
    uint8_t sbox_index,
    uint8_t input,
    uint8_t faulty_output
);

int scenery_fault_is_active(void);
uint8_t scenery_fault_sbox_index(void);
uint8_t scenery_fault_input(void);
uint8_t scenery_fault_output(void);
uint8_t scenery_fault_correct_output(void);

uint8_t scenery_sbox_correct(uint8_t input);
uint8_t scenery_sbox_faulty(uint8_t sbox_index, uint8_t input);

/*
 * Parallel faulty encryption path. The validated reference path in
 * scenery_encrypt_block() is left unchanged.
 */
int scenery_encrypt_block_faulty(
    const scenery_ctx *ctx,
    const uint8_t plaintext[SCENERY_BLOCK_SIZE],
    uint8_t ciphertext[SCENERY_BLOCK_SIZE]
);

#ifdef __cplusplus
}
#endif

#endif /* PERSISTENT_FAULT_H */
