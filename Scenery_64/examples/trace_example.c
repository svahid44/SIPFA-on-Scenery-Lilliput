#include "scenery.h"

#include <inttypes.h>
#include <stdio.h>

int main(void)
{
    const uint8_t key[SCENERY_KEY_SIZE] = {0};
    const uint8_t plaintext[SCENERY_BLOCK_SIZE] = {0};
    scenery_ctx ctx;
    scenery_round_trace trace[SCENERY_ROUNDS];
    uint8_t ciphertext[SCENERY_BLOCK_SIZE];
    size_t i;

    if (scenery_init(&ctx, key) != 0 ||
        scenery_encrypt_block_trace(&ctx, plaintext, ciphertext, trace) != 0) {
        return 1;
    }

    puts("rnd  key       Lin       Rin       add       sub       mix       Lout      Rout");
    for (i = 0u; i < SCENERY_ROUNDS; ++i) {
        printf("%3zu  %08" PRIX32 "  %08" PRIX32 "  %08" PRIX32
               "  %08" PRIX32 "  %08" PRIX32 "  %08" PRIX32
               "  %08" PRIX32 "  %08" PRIX32 "\n",
               trace[i].round_number,
               trace[i].round_key,
               trace[i].left_in,
               trace[i].right_in,
               trace[i].after_add_key,
               trace[i].after_subcolumns,
               trace[i].after_mixcolumns,
               trace[i].left_out,
               trace[i].right_out);
    }
    return 0;
}
