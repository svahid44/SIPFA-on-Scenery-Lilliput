#!/usr/bin/env sh
set -eu

ciphertext_attack_sources="
src/known_detection_iterative.c
src/unknown_detection_attack.c
src/known_infection_attack.c
src/unknown_infection_attack.c
src/attack_round.c
"

for source in $ciphertext_attack_sources; do
    if grep -Eq 'reference_validation|reference_trace|lilliput_reference_round_tweakey|lilliput_reference_encrypt_trace|tweakey_state_|actual_rtk|master_key' "$source"; then
        echo "FAIL: forbidden validation/secret dependency in $source" >&2
        exit 1
    fi
done

full_recovery_source="src/unknown_infection_full_recovery.c"
if grep -Eq 'reference_validation|reference_trace|lilliput_reference_|actual_key|actual_rtk|event_label|fault_output' "$full_recovery_source"; then
    echo "FAIL: forbidden validation/secret dependency in $full_recovery_source" >&2
    exit 1
fi

schedule_source="src/master_key_recovery.c"
if grep -Eq 'reference_validation|reference_trace|lilliput_reference_|lilliput_tbc_encrypt|actual_key|actual_rtk|plaintext|ciphertext' "$schedule_source"; then
    echo "FAIL: validation/known-data dependency in $schedule_source" >&2
    exit 1
fi

if grep -Eq 'const uint8_t plaintext' include/detection_dataset.h; then
    echo "FAIL: detection callback exposes plaintext" >&2
    exit 1
fi

if ! grep -q 'const uint8_t ciphertext\[BLOCK_BYTES\]' include/detection_dataset.h; then
    echo "FAIL: detection callback does not expose the accepted ciphertext" >&2
    exit 1
fi

if grep -Eq 'key\[KEY_BYTES\]|tweak\[TWEAK_BYTES\]|plaintext\[BLOCK_BYTES\]|actual_rtk|reference_' include/known_detection_iterative.h; then
    echo "FAIL: iterative known-detection API exposes forbidden secret/validation inputs" >&2
    exit 1
fi

if ! grep -q 'accepted_ciphertexts' include/known_detection_iterative.h; then
    echo "FAIL: iterative known-detection API does not expose accepted ciphertexts" >&2
    exit 1
fi

if grep -Eq 'actual_key|actual_rtk|plaintext|ciphertext|reference_' include/master_key_recovery.h; then
    echo "FAIL: master-key API exposes validation or known-data inputs" >&2
    exit 1
fi

if ! grep -q 'public_tweak' include/master_key_recovery.h ||
   ! grep -q 'recovered_rtk30' include/master_key_recovery.h ||
   ! grep -q 'recovered_rtk31' include/master_key_recovery.h; then
    echo "FAIL: master-key API is missing public tweak or recovered RTK inputs" >&2
    exit 1
fi

full_unknown_header="include/unknown_infection_full_recovery.h"
if grep -Eq 'actual_key|actual_rtk|event_label|fault_output|reference_' "$full_unknown_header"; then
    echo "FAIL: Scenario-4 full-key API exposes forbidden secret/validation inputs" >&2
    exit 1
fi

if ! grep -q 'published_ciphertexts' "$full_unknown_header" ||
   ! grep -q 'public_tweak' "$full_unknown_header"; then
    echo "FAIL: Scenario-4 full-key API is missing public ciphertext or tweak inputs" >&2
    exit 1
fi

echo "PASS: attack-source boundary audit completed."
