#include <stddef.h>
#include <stdint.h>

#include "constants.h"
#include "reference_validation.h"
#include "tweakey.h"

int lilliput_reference_round_tweakey(
    const uint8_t key[KEY_BYTES],
    const uint8_t tweak[TWEAK_BYTES],
    size_t round_index,
    uint8_t round_tweakey[ROUND_TWEAKEY_BYTES]
)
{
    uint8_t tweakey_state[TWEAKEY_BYTES];

    if ((key == NULL) || (tweak == NULL) || (round_tweakey == NULL) ||
        (round_index >= ROUNDS)) {
        return -1;
    }

    tweakey_state_init(tweakey_state, key, tweak);
    for (size_t round = 0U; round < round_index; ++round) {
        tweakey_state_update(tweakey_state);
    }
    tweakey_state_extract(tweakey_state, (uint8_t)round_index, round_tweakey);
    return 0;
}
