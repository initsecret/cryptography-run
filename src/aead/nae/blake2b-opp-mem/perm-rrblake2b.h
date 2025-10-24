/*
    The Four-Round (Reduced Round) Blake2b Permutation

    Adapted from:

    OPP - MEM AEAD source code package

    :copyright: (c) 2015 by Philipp Jovanovic and Samuel Neves
    :license: Creative Commons CC0 1.0
*/

#ifndef CR_PERM_BLAKE2B_H
#define CR_PERM_BLAKE2B_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if 0  // defined(__x86_64__)

#include <immintrin.h>

#include "../../../internal.h"

#include "v0.h"
#include "v1.h"
#include "v4.h"

// Use the 4-round variant
#define OPP_R 4

#if defined(__cplusplus)
extern "C" {
#endif

typedef union {
  u256_t inner[4];
  __m256i inner_intel[4];
} rrblake2b_block;

typedef struct {
  u256_t inner[16];
  __m256i inner_intel[16];
} rrblake2b_block_x4;

static rrblake2b_block zero_block() {
  rrblake2b_block in = {{zero256(), zero256(), zero256(), zero256()}};
  return in;
}

static rrblake2b_block load_block(const uint8_t *in) {
  rrblake2b_block out = {
      {load256(in), load256(in + 32), load256(in + 64), load256(in + 96)}};
  return out;
}
static void store_block(uint8_t *out, rrblake2b_block in) {
  for (int i = 0; i < 4; i++) {
    store256(out + (i * 32), in.inner[i]);
  }
}

static void Perm_forward(rrblake2b_block *state) {
  V1_PERMUTE_F(state->inner->intel256);
}

static void Perm_forward_x4(rrblake2b_block_x4 *state_x4) {
  V4_PERMUTE_F(state_x4->inner);
}

static void Perm_backward(rrblake2b_block *state) {
  V1_PERMUTE_B(state->inner);
}

#ifdef __cplusplus
}
#endif

#endif  // __x86_64__

#endif  // CR_PERM_BLAKE2b_H
