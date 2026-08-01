#include "scenery.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    size_t round_number;
    uint32_t round_key;
    uint32_t left_in;
    uint32_t right_in;
    uint32_t after_add_key;
    uint32_t after_subcolumns;
    uint32_t after_mixcolumns;
    uint32_t left_out;
    uint32_t right_out;
} expected_trace;

static const expected_trace EXPECTED[SCENERY_ROUNDS] = {
    { 1u, UINT32_C(0x00000000), UINT32_C(0x00000000), UINT32_C(0x00000000),
      UINT32_C(0x00000000), UINT32_C(0x00FFFF00), UINT32_C(0xFF0000FF),
      UINT32_C(0xFF0000FF), UINT32_C(0x00000000) },
    { 2u, UINT32_C(0x30013000), UINT32_C(0xFF0000FF), UINT32_C(0x00000000),
      UINT32_C(0xCF0130FF), UINT32_C(0x01000131), UINT32_C(0x60201037),
      UINT32_C(0x60201037), UINT32_C(0xFF0000FF) },
    { 3u, UINT32_C(0x30000000), UINT32_C(0x60201037), UINT32_C(0xFF0000FF),
      UINT32_C(0x50201037), UINT32_C(0x77BFD817), UINT32_C(0x4C2E1822),
      UINT32_C(0xB32E18DD), UINT32_C(0x60201037) },
    { 4u, UINT32_C(0x30033000), UINT32_C(0xB32E18DD), UINT32_C(0x60201037),
      UINT32_C(0x832D28DD), UINT32_C(0x77742B51), UINT32_C(0xDB726869),
      UINT32_C(0xBB52785E), UINT32_C(0xB32E18DD) },
    { 5u, UINT32_C(0x608C0180), UINT32_C(0xBB52785E), UINT32_C(0xB32E18DD),
      UINT32_C(0xDBDE79DE), UINT32_C(0xA65D8383), UINT32_C(0xC733BC4F),
      UINT32_C(0x741DA492), UINT32_C(0xBB52785E) },
    { 6u, UINT32_C(0x4009328C), UINT32_C(0x741DA492), UINT32_C(0xBB52785E),
      UINT32_C(0x3414961E), UINT32_C(0xA85D610A), UINT32_C(0x85F20323),
      UINT32_C(0x3EA07B7D), UINT32_C(0x741DA492) },
    { 7u, UINT32_C(0x410C0018), UINT32_C(0x3EA07B7D), UINT32_C(0x741DA492),
      UINT32_C(0x7FAC7B65), UINT32_C(0x4D73D7DF), UINT32_C(0x1C3C85A9),
      UINT32_C(0x6821213B), UINT32_C(0x3EA07B7D) },
    { 8u, UINT32_C(0x4007D814), UINT32_C(0x6821213B), UINT32_C(0x3EA07B7D),
      UINT32_C(0x2826F92F), UINT32_C(0xDE2E0809), UINT32_C(0x30A988A1),
      UINT32_C(0x0E09F3DC), UINT32_C(0x6821213B) },
    { 9u, UINT32_C(0x64904200), UINT32_C(0x0E09F3DC), UINT32_C(0x6821213B),
      UINT32_C(0x6A99B1DC), UINT32_C(0x0F25BB2C), UINT32_C(0x688E0E30),
      UINT32_C(0x00AF2F0B), UINT32_C(0x0E09F3DC) },
    { 10u, UINT32_C(0xB2193276), UINT32_C(0x00AF2F0B), UINT32_C(0x0E09F3DC),
      UINT32_C(0xB2B61D7D), UINT32_C(0x60D224EB), UINT32_C(0xB17BD28B),
      UINT32_C(0xBF722157), UINT32_C(0x00AF2F0B) },
    { 11u, UINT32_C(0xBA238220), UINT32_C(0xBF722157), UINT32_C(0x00AF2F0B),
      UINT32_C(0x0551A377), UINT32_C(0xD0590822), UINT32_C(0x9CF13A76),
      UINT32_C(0x9C5E157D), UINT32_C(0xBF722157) },
    { 12u, UINT32_C(0x840CCDD1), UINT32_C(0x9C5E157D), UINT32_C(0xBF722157),
      UINT32_C(0x1852D8AC), UINT32_C(0x7C6D4BBE), UINT32_C(0x4A3836AA),
      UINT32_C(0xF54A17FD), UINT32_C(0x9C5E157D) },
    { 13u, UINT32_C(0x4662AAA0), UINT32_C(0xF54A17FD), UINT32_C(0x9C5E157D),
      UINT32_C(0xB328BD5D), UINT32_C(0x73D19BF5), UINT32_C(0x111CF3D6),
      UINT32_C(0x8D42E6AB), UINT32_C(0xF54A17FD) },
    { 14u, UINT32_C(0x00324B21), UINT32_C(0x8D42E6AB), UINT32_C(0xF54A17FD),
      UINT32_C(0x8D70AD8A), UINT32_C(0xAAAFFDDF), UINT32_C(0xA0A5FBFD),
      UINT32_C(0x55EFEC00), UINT32_C(0x8D42E6AB) },
    { 15u, UINT32_C(0x9B2AC1B4), UINT32_C(0x55EFEC00), UINT32_C(0x8D42E6AB),
      UINT32_C(0xCEC52DB4), UINT32_C(0x935D8BF8), UINT32_C(0x2C951387),
      UINT32_C(0xA1D7F52C), UINT32_C(0x55EFEC00) },
    { 16u, UINT32_C(0x0F12B940), UINT32_C(0xA1D7F52C), UINT32_C(0x55EFEC00),
      UINT32_C(0xAEC54C6C), UINT32_C(0x0A9C5B89), UINT32_C(0xFAE4751F),
      UINT32_C(0xAF0B991F), UINT32_C(0xA1D7F52C) },
    { 17u, UINT32_C(0xC8F01458), UINT32_C(0xAF0B991F), UINT32_C(0xA1D7F52C),
      UINT32_C(0x67FB8D47), UINT32_C(0xCEADDE76), UINT32_C(0x312F0414),
      UINT32_C(0x90F8F138), UINT32_C(0xAF0B991F) },
    { 18u, UINT32_C(0xB0B3D803), UINT32_C(0x90F8F138), UINT32_C(0xAF0B991F),
      UINT32_C(0x204B293B), UINT32_C(0x32B6ED70), UINT32_C(0xA79D31D2),
      UINT32_C(0x0896A8CD), UINT32_C(0x90F8F138) },
    { 19u, UINT32_C(0x19B23D85), UINT32_C(0x0896A8CD), UINT32_C(0x90F8F138),
      UINT32_C(0x11249548), UINT32_C(0xCC5F3779), UINT32_C(0x1478CED6),
      UINT32_C(0x84803FEE), UINT32_C(0x0896A8CD) },
    { 20u, UINT32_C(0x92B1CBB4), UINT32_C(0x84803FEE), UINT32_C(0x0896A8CD),
      UINT32_C(0x1631F45A), UINT32_C(0xA83C254D), UINT32_C(0x4751BB37),
      UINT32_C(0x4FC713FA), UINT32_C(0x84803FEE) },
    { 21u, UINT32_C(0x8B466F0F), UINT32_C(0x4FC713FA), UINT32_C(0x84803FEE),
      UINT32_C(0xC4817CF5), UINT32_C(0xCD47C6F4), UINT32_C(0x4470045C),
      UINT32_C(0xC0F03BB2), UINT32_C(0x4FC713FA) },
    { 22u, UINT32_C(0xADA4AD72), UINT32_C(0xC0F03BB2), UINT32_C(0x4FC713FA),
      UINT32_C(0x6D5496C0), UINT32_C(0x7F1079C4), UINT32_C(0x10DFC726),
      UINT32_C(0x5F18D4DC), UINT32_C(0xC0F03BB2) },
    { 23u, UINT32_C(0x0D7DE262), UINT32_C(0x5F18D4DC), UINT32_C(0xC0F03BB2),
      UINT32_C(0x526536BE), UINT32_C(0x9ADA37DB), UINT32_C(0x403CE4A8),
      UINT32_C(0x80CCDF1A), UINT32_C(0x5F18D4DC) },
    { 24u, UINT32_C(0x668EDB45), UINT32_C(0x80CCDF1A), UINT32_C(0x5F18D4DC),
      UINT32_C(0xE642045F), UINT32_C(0xFF1DE65F), UINT32_C(0x3AD8DED3),
      UINT32_C(0x65C00A0F), UINT32_C(0x80CCDF1A) },
    { 25u, UINT32_C(0x5B435FF8), UINT32_C(0x65C00A0F), UINT32_C(0x80CCDF1A),
      UINT32_C(0x3E8355F7), UINT32_C(0x9E941F56), UINT32_C(0x5D6E4491),
      UINT32_C(0xDDA29B8B), UINT32_C(0x65C00A0F) },
    { 26u, UINT32_C(0x13BDDADA), UINT32_C(0xDDA29B8B), UINT32_C(0x65C00A0F),
      UINT32_C(0xCE1F4151), UINT32_C(0xD07EE14E), UINT32_C(0xD298C6EE),
      UINT32_C(0xB758CCE1), UINT32_C(0xDDA29B8B) },
    { 27u, UINT32_C(0x9A9736C8), UINT32_C(0xB758CCE1), UINT32_C(0xDDA29B8B),
      UINT32_C(0x2DCFFA29), UINT32_C(0xF3EEE325), UINT32_C(0x5F4D7631),
      UINT32_C(0x82EFEDBA), UINT32_C(0xB758CCE1) },
    { 28u, UINT32_C(0xEFF664D4), UINT32_C(0x82EFEDBA), UINT32_C(0xB758CCE1),
      UINT32_C(0x6D19896E), UINT32_C(0x830A1013), UINT32_C(0x846E0173),
      UINT32_C(0x3336CD92), UINT32_C(0x82EFEDBA) }
};

int main(void)
{
    const uint8_t key[SCENERY_KEY_SIZE] = {0};
    const uint8_t plaintext[SCENERY_BLOCK_SIZE] = {0};
    const uint8_t expected_ciphertext[SCENERY_BLOCK_SIZE] = {
        0x82,0xEF,0xED,0xBA,0x33,0x36,0xCD,0x92
    };
    scenery_ctx ctx;
    scenery_round_trace trace[SCENERY_ROUNDS];
    uint8_t ciphertext[SCENERY_BLOCK_SIZE];
    size_t i;

    if (scenery_init(&ctx, key) != 0 ||
        scenery_encrypt_block_trace(&ctx, plaintext, ciphertext, trace) != 0) {
        fputs("FAIL: API error\n", stderr);
        return 1;
    }
    if (memcmp(ciphertext, expected_ciphertext, SCENERY_BLOCK_SIZE) != 0) {
        fputs("FAIL: final ciphertext mismatch\n", stderr);
        return 1;
    }

    for (i = 0u; i < SCENERY_ROUNDS; ++i) {
        const expected_trace *e = &EXPECTED[i];
        const scenery_round_trace *a = &trace[i];
        if (a->round_number != e->round_number ||
            a->round_key != e->round_key ||
            a->left_in != e->left_in ||
            a->right_in != e->right_in ||
            a->after_add_key != e->after_add_key ||
            a->after_subcolumns != e->after_subcolumns ||
            a->after_mixcolumns != e->after_mixcolumns ||
            a->left_out != e->left_out ||
            a->right_out != e->right_out) {
            fprintf(stderr, "FAIL: trace mismatch at round %zu\n", i + 1u);
            fprintf(stderr,
                    "actual key=%08" PRIX32 " L=%08" PRIX32
                    " R=%08" PRIX32 " add=%08" PRIX32
                    " sub=%08" PRIX32 " mix=%08" PRIX32
                    " L'=%08" PRIX32 " R'=%08" PRIX32 "\n",
                    a->round_key, a->left_in, a->right_in,
                    a->after_add_key, a->after_subcolumns,
                    a->after_mixcolumns, a->left_out, a->right_out);
            return 1;
        }
    }

    puts("PASS: all 28 encryption-round trace records match round_trace_tv1.json.");
    return 0;
}
