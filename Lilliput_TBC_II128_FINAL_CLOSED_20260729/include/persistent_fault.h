#ifndef PERSISTENT_FAULT_H
#define PERSISTENT_FAULT_H

#include <stdint.h>

/*
 * Persistent lookup-table fault model for the shared 8-bit Lilliput S-box.
 *
 * The correct S-box is immutable.  The faulty S-box initially equals the
 * correct table; lilliput_fault_inject() changes exactly one entry and that
 * change persists across subsequent faulty encryptions until reset.
 */

void lilliput_fault_reset(void);

/*
 * Inject S_faulty[input] = faulty_output.
 * Returns 0 on success and -1 if faulty_output equals the correct output.
 */
int lilliput_fault_inject(uint8_t input, uint8_t faulty_output);

int lilliput_fault_is_active(void);
uint8_t lilliput_fault_input(void);
uint8_t lilliput_fault_output(void);
uint8_t lilliput_fault_correct_output(void);

/* Lookup functions used by the cipher core. */
uint8_t lilliput_sbox_correct(uint8_t input);
uint8_t lilliput_sbox_faulty(uint8_t input);

#endif /* PERSISTENT_FAULT_H */
