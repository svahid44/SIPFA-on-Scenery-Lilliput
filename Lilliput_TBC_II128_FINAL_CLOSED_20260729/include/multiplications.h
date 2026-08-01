/*
Implementation of the Lilliput-AE tweakable block cipher.

Authors, hereby denoted as "the implementer":
    Kévin Le Gouguec,
    2019.

For more information, feedback or questions, refer to our website:
https://paclido.fr/lilliput-ae

To the extent possible under law, the implementer has waived all copyright
and related or neighboring rights to the source code in this file.
http://creativecommons.org/publicdomain/zero/1.0/

---

This file implements the alpha-multiplications used in Lilliput-TBC's
tweakey schedule, where each matrix M and M_R to the power n are
implemented in distinct functions with shifts and XORs.
*/
#ifndef MULTIPLICATIONS_H
#define MULTIPLICATIONS_H

#include <stdint.h>
#include "constants.h"

static void _multiply_M(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    y[7] = x[6];
    y[6] = x[5];
    y[5] = (uint8_t)((x[5] << 3) ^ x[4]);
    y[4] = (uint8_t)((x[4] >> 3) ^ x[3]);
    y[3] = x[2];
    y[2] = (uint8_t)((x[6] << 2) ^ x[1]);
    y[1] = x[0];
    y[0] = x[7];
}

static void _multiply_M2(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    uint8_t a5 = (uint8_t)((x[5] << 3) ^ x[4]);
    uint8_t a4 = (uint8_t)((x[4] >> 3) ^ x[3]);

    y[7] = x[5];
    y[6] = a5;
    y[5] = (uint8_t)((a5 << 3) ^ a4);
    y[4] = (uint8_t)((a4 >> 3) ^ x[2]);
    y[3] = (uint8_t)((x[6] << 2) ^ x[1]);
    y[2] = (uint8_t)((x[5] << 2) ^ x[0]);
    y[1] = x[7];
    y[0] = x[6];
}

static void _multiply_M3(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    uint8_t a5 = (uint8_t)((x[5] << 3) ^ x[4]);
    uint8_t a4 = (uint8_t)((x[4] >> 3) ^ x[3]);
    uint8_t b5 = (uint8_t)((a5 << 3) ^ a4);
    uint8_t b4 = (uint8_t)((a4 >> 3) ^ x[2]);

    y[7] = a5;
    y[6] = b5;
    y[5] = (uint8_t)((b5 << 3) ^ b4);
    y[4] = (uint8_t)((b4 >> 3) ^ (x[6] << 2) ^ x[1]);
    y[3] = (uint8_t)((x[5] << 2) ^ x[0]);
    y[2] = (uint8_t)((a5 << 2) ^ x[7]);
    y[1] = x[6];
    y[0] = x[5];
}

static void _multiply_M4(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    uint8_t a5 = (uint8_t)((x[5] << 3) ^ x[4]);
    uint8_t a4 = (uint8_t)((x[4] >> 3) ^ x[3]);
    uint8_t b5 = (uint8_t)((a5 << 3) ^ a4);
    uint8_t b4 = (uint8_t)((a4 >> 3) ^ x[2]);
    uint8_t c4 = (uint8_t)((b4 >> 3) ^ (x[6] << 2) ^ x[1]);
    uint8_t c5 = (uint8_t)((b5 << 3) ^ b4);

    y[7] = b5;
    y[6] = c5;
    y[5] = (uint8_t)((c5 << 3) ^ c4);
    y[4] = (uint8_t)((c4 >> 3) ^ (x[5] << 2) ^ x[0]);
    y[3] = (uint8_t)((a5 << 2) ^ x[7]);
    y[2] = (uint8_t)((b5 << 2) ^ x[6]);
    y[1] = x[5];
    y[0] = a5;
}

static void _multiply_MR(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    y[0] = x[1];
    y[1] = x[2];
    y[2] = (uint8_t)(x[3] ^ (x[4] >> 3));
    y[3] = x[4];
    y[4] = (uint8_t)(x[5] ^ (x[6] << 3));
    y[5] = (uint8_t)((x[3] << 2) ^ x[6]);
    y[6] = x[7];
    y[7] = x[0];
}

static void _multiply_MR2(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    uint8_t a4 = (uint8_t)(x[5] ^ (x[6] << 3));

    y[0] = x[2];
    y[1] = (uint8_t)(x[3] ^ (x[4] >> 3));
    y[2] = (uint8_t)(x[4] ^ (a4 >> 3));
    y[3] = a4;
    y[4] = (uint8_t)((x[3] << 2) ^ x[6] ^ (x[7] << 3));
    y[5] = (uint8_t)((x[4] << 2) ^ x[7]);
    y[6] = x[0];
    y[7] = x[1];
}

static void _multiply_MR3(const uint8_t x[LANE_BYTES], uint8_t y[LANE_BYTES])
{
    uint8_t a4 = (uint8_t)(x[5] ^ (x[6] << 3));
    uint8_t b4 = (uint8_t)((x[3] << 2) ^ x[6] ^ (x[7] << 3));

    y[0] = (uint8_t)(x[3] ^ (x[4] >> 3));
    y[1] = (uint8_t)(x[4] ^ (a4 >> 3));
    y[2] = (uint8_t)(a4 ^ (b4 >> 3));
    y[3] = b4;
    y[4] = (uint8_t)((x[0] << 3) ^ (x[4] << 2) ^ x[7]);
    y[5] = (uint8_t)((a4 << 2) ^ x[0]);
    y[6] = x[1];
    y[7] = x[2];
}

#endif /* MULTIPLICATIONS_H */
