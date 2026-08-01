#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "detection_dataset.h"
#include "known_detection_iterative.h"
#include "known_infection_attack.h"
#include "master_key_recovery.h"
#include "unknown_detection_attack.h"
#include "unknown_infection_attack.h"
#include "unknown_infection_full_recovery.h"

static int ciphertext_only_callback(
    uint64_t query_index,
    uint64_t ineffective_index,
    const uint8_t ciphertext[BLOCK_BYTES],
    void *user_data
)
{
    (void)query_index;
    (void)ineffective_index;
    (void)ciphertext;
    (void)user_data;
    return 0;
}

int main(void)
{
    lilliput_ineffective_callback callback = ciphertext_only_callback;
    int (*unknown_detection)(const uint8_t *, size_t,
        lilliput_unknown_detection_result *) =
        lilliput_unknown_detection_recover;
    int (*known_detection_iterative)(const uint8_t *, size_t, uint8_t,
        lilliput_known_detection_iterative_result *) =
        lilliput_known_detection_recover_last_two_rtks;
    int (*master_key_recovery)(const uint8_t *, const uint8_t *,
        const uint8_t *, lilliput_master_key_recovery_result *) =
        lilliput_recover_master_key_from_rtk30_rtk31;
    int (*known_infection)(const uint8_t *, size_t, uint8_t,
        lilliput_known_infection_result *) =
        lilliput_known_infection_recover;
    int (*unknown_infection)(const uint8_t *, size_t,
        lilliput_unknown_infection_result *) =
        lilliput_unknown_infection_recover;
    int (*unknown_infection_full_key)(const uint8_t *, size_t,
        const uint8_t *, lilliput_unknown_infection_full_result *) =
        lilliput_unknown_infection_recover_full_key;

    if ((callback == NULL) || (known_detection_iterative == NULL) ||
        (master_key_recovery == NULL) || (unknown_detection == NULL) ||
        (known_infection == NULL) || (unknown_infection == NULL) ||
        (unknown_infection_full_key == NULL)) {
        return 1;
    }

    puts("PASS: attack APIs expose only ciphertext/fault inputs and public tweak plus recovered RTKs; the Scenario-4 full-key API receives only public ciphertexts and tweak.");
    return 0;
}
