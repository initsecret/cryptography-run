///////////////////////////////////////////////////////////////////////////////
// sparkle_opt.c: Optimized C99 implementation of the SPARKLE permutation.   //
// This file is part of the SPARKLE submission to NIST's LW Crypto Project.  //
// Version 1.1.2 (2020-10-30), see <http://www.cryptolux.org/> for updates.  //
// Authors: The SPARKLE Group (C. Beierle, A. Biryukov, L. Cardoso dos       //
// Santos, J. Groszschaedl, L. Perrin, A. Udovenko, V. Velichkov, Q. Wang).  //
// License: GPLv3 (see LICENSE file), other licenses available upon request. //
// Copyright (C) 2019-2020 University of Luxembourg <http://www.uni.lu/>.    //
// ------------------------------------------------------------------------- //
// This program is free software: you can redistribute it and/or modify it   //
// under the terms of the GNU General Public License as published by the     //
// Free Software Foundation, either version 3 of the License, or (at your    //
// option) any later version. This program is distributed in the hope that   //
// it will be useful, but WITHOUT ANY WARRANTY; without even the implied     //
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the  //
// GNU General Public License for more details. You should have received a   //
// copy of the GNU General Public License along with this program. If not,   //
// see <http://www.gnu.org/licenses/>.                                       //
///////////////////////////////////////////////////////////////////////////////

#ifndef CR_SPARKLE_H
#define CR_SPARKLE_H

#include <cryptography-run/base.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define SPARKLE256_STATE 256
#define SPARKLE256_STEPS_SLIM 7
#define SPARKLE256_STEPS_BIG 10
#define SPARKLE256_BRANS 4  // (SPARKLE256_STATE / 64)

#define MAX_BRANCHES 8

#define SPARKLE256_STATE_WORDS (SPARKLE256_STATE / 32)
#define SPARKLE256_STATE_BYTES (SPARKLE256_STATE / 8)

#define ROT(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define ELL(x) (ROT(((x) ^ ((x) << 16)), 16))

// Round constants
static const uint32_t RCON[MAX_BRANCHES] = {0xB7E15162, 0xBF715880, 0x38B4DA56,
                                            0x324E7738, 0xBB1185EB, 0x4F7C7B57,
                                            0xCFBFA1C8, 0xC2B3293D};

static void sparkle256_opt(uint32_t *state, int brans, int steps) {
  int i, j;  // Step and branch counter
  uint32_t rc, tmpx, tmpy, x0, y0;

  for (i = 0; i < steps; i++) {
    // Add round constant
    state[1] ^= RCON[i % MAX_BRANCHES];
    state[3] ^= i;
    // ARXBOX layer
    for (j = 0; j < 2 * brans; j += 2) {
      rc = RCON[j >> 1];
      state[j] += ROT(state[j + 1], 31);
      state[j + 1] ^= ROT(state[j], 24);
      state[j] ^= rc;
      state[j] += ROT(state[j + 1], 17);
      state[j + 1] ^= ROT(state[j], 17);
      state[j] ^= rc;
      state[j] += state[j + 1];
      state[j + 1] ^= ROT(state[j], 31);
      state[j] ^= rc;
      state[j] += ROT(state[j + 1], 24);
      state[j + 1] ^= ROT(state[j], 16);
      state[j] ^= rc;
    }
    // Linear layer
    tmpx = x0 = state[0];
    tmpy = y0 = state[1];
    for (j = 2; j < brans; j += 2) {
      tmpx ^= state[j];
      tmpy ^= state[j + 1];
    }
    tmpx = ELL(tmpx);
    tmpy = ELL(tmpy);
    for (j = 2; j < brans; j += 2) {
      state[j - 2] = state[j + brans] ^ state[j] ^ tmpy;
      state[j + brans] = state[j];
      state[j - 1] = state[j + brans + 1] ^ state[j + 1] ^ tmpx;
      state[j + brans + 1] = state[j + 1];
    }
    state[brans - 2] = state[brans] ^ x0 ^ tmpy;
    state[brans] = x0;
    state[brans - 1] = state[brans + 1] ^ y0 ^ tmpx;
    state[brans + 1] = y0;
  }
}

static void sparkle256_inv_opt(uint32_t *state, int brans, int steps) {
  int i, j;  // Step and branch counter
  uint32_t rc, tmpx, tmpy, xb1, yb1;

  for (i = steps - 1; i >= 0; i--) {
    // Linear layer
    tmpx = tmpy = 0;
    xb1 = state[brans - 2];
    yb1 = state[brans - 1];
    for (j = brans - 2; j > 0; j -= 2) {
      tmpx ^= (state[j] = state[j + brans]);
      state[j + brans] = state[j - 2];
      tmpy ^= (state[j + 1] = state[j + brans + 1]);
      state[j + brans + 1] = state[j - 1];
    }
    tmpx ^= (state[0] = state[brans]);
    state[brans] = xb1;
    tmpy ^= (state[1] = state[brans + 1]);
    state[brans + 1] = yb1;
    tmpx = ELL(tmpx);
    tmpy = ELL(tmpy);
    for (j = brans - 2; j >= 0; j -= 2) {
      state[j + brans] ^= (tmpy ^ state[j]);
      state[j + brans + 1] ^= (tmpx ^ state[j + 1]);
    }
    // ARXBOX layer
    for (j = 0; j < 2 * brans; j += 2) {
      rc = RCON[j >> 1];
      state[j] ^= rc;
      state[j + 1] ^= ROT(state[j], 16);
      state[j] -= ROT(state[j + 1], 24);
      state[j] ^= rc;
      state[j + 1] ^= ROT(state[j], 31);
      state[j] -= state[j + 1];
      state[j] ^= rc;
      state[j + 1] ^= ROT(state[j], 17);
      state[j] -= ROT(state[j + 1], 17);
      state[j] ^= rc;
      state[j + 1] ^= ROT(state[j], 24);
      state[j] -= ROT(state[j + 1], 31);
    }
    // Add round constant
    state[1] ^= RCON[i % MAX_BRANCHES];
    state[3] ^= i;
  }
}

static void perm_sparkle256big_forward(u256_t *state) {
  sparkle256_opt(state->u32, SPARKLE256_BRANS, SPARKLE256_STEPS_BIG);
}
static void perm_sparkle256big_backward(u256_t *state) {
  sparkle256_inv_opt(state->u32, SPARKLE256_BRANS, SPARKLE256_STEPS_BIG);
}

#define SPARKLE512_STATE 512
#define SPARKLE512_STEPS_SLIM 8
#define SPARKLE512_STEPS_BIG 12
#define SPARKLE512_BRANS 8  // (SPARKLE512_STATE / 64)

#define SPARKLE512_STATE_WORDS (SPARKLE512_STATE / 32)
#define SPARKLE512_STATE_BYTES (SPARKLE512_STATE / 8)

static void sparkle512_opt(uint32_t *state, int brans, int steps) {
  int i, j;  // Step and branch counter
  uint32_t rc, tmpx, tmpy, x0, y0;

  for (i = 0; i < steps; i++) {
    // Add round constant
    state[1] ^= RCON[i % MAX_BRANCHES];
    state[3] ^= i;
    // ARXBOX layer
    for (j = 0; j < 2 * brans; j += 2) {
      rc = RCON[j >> 1];
      state[j] += ROT(state[j + 1], 31);
      state[j + 1] ^= ROT(state[j], 24);
      state[j] ^= rc;
      state[j] += ROT(state[j + 1], 17);
      state[j + 1] ^= ROT(state[j], 17);
      state[j] ^= rc;
      state[j] += state[j + 1];
      state[j + 1] ^= ROT(state[j], 31);
      state[j] ^= rc;
      state[j] += ROT(state[j + 1], 24);
      state[j + 1] ^= ROT(state[j], 16);
      state[j] ^= rc;
    }
    // Linear layer
    tmpx = x0 = state[0];
    tmpy = y0 = state[1];
    for (j = 2; j < brans; j += 2) {
      tmpx ^= state[j];
      tmpy ^= state[j + 1];
    }
    tmpx = ELL(tmpx);
    tmpy = ELL(tmpy);
    for (j = 2; j < brans; j += 2) {
      state[j - 2] = state[j + brans] ^ state[j] ^ tmpy;
      state[j + brans] = state[j];
      state[j - 1] = state[j + brans + 1] ^ state[j + 1] ^ tmpx;
      state[j + brans + 1] = state[j + 1];
    }
    state[brans - 2] = state[brans] ^ x0 ^ tmpy;
    state[brans] = x0;
    state[brans - 1] = state[brans + 1] ^ y0 ^ tmpx;
    state[brans + 1] = y0;
  }
}

static void sparkle512_inv_opt(uint32_t *state, int brans, int steps) {
  int i, j;  // Step and branch counter
  uint32_t rc, tmpx, tmpy, xb1, yb1;

  for (i = steps - 1; i >= 0; i--) {
    // Linear layer
    tmpx = tmpy = 0;
    xb1 = state[brans - 2];
    yb1 = state[brans - 1];
    for (j = brans - 2; j > 0; j -= 2) {
      tmpx ^= (state[j] = state[j + brans]);
      state[j + brans] = state[j - 2];
      tmpy ^= (state[j + 1] = state[j + brans + 1]);
      state[j + brans + 1] = state[j - 1];
    }
    tmpx ^= (state[0] = state[brans]);
    state[brans] = xb1;
    tmpy ^= (state[1] = state[brans + 1]);
    state[brans + 1] = yb1;
    tmpx = ELL(tmpx);
    tmpy = ELL(tmpy);
    for (j = brans - 2; j >= 0; j -= 2) {
      state[j + brans] ^= (tmpy ^ state[j]);
      state[j + brans + 1] ^= (tmpx ^ state[j + 1]);
    }
    // ARXBOX layer
    for (j = 0; j < 2 * brans; j += 2) {
      rc = RCON[j >> 1];
      state[j] ^= rc;
      state[j + 1] ^= ROT(state[j], 16);
      state[j] -= ROT(state[j + 1], 24);
      state[j] ^= rc;
      state[j + 1] ^= ROT(state[j], 31);
      state[j] -= state[j + 1];
      state[j] ^= rc;
      state[j + 1] ^= ROT(state[j], 17);
      state[j] -= ROT(state[j + 1], 17);
      state[j] ^= rc;
      state[j + 1] ^= ROT(state[j], 24);
      state[j] -= ROT(state[j + 1], 31);
    }
    // Add round constant
    state[1] ^= RCON[i % MAX_BRANCHES];
    state[3] ^= i;
  }
}

static void perm_sparkle512big_forward(u512_t *state) {
  sparkle512_opt(state->u32, SPARKLE512_BRANS, SPARKLE512_STEPS_BIG);
}
static void perm_sparkle512big_backward(u512_t *state) {
  sparkle512_inv_opt(state->u32, SPARKLE512_BRANS, SPARKLE512_STEPS_BIG);
}

#ifdef __cplusplus
}
#endif
#endif  // CR_SPARKLE_H