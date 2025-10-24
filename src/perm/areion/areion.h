/* Copyright (c) 2023 GMO Cybersecurity by Ierae, Inc. All rights reserved. */
/* This software is implemented based on the algorithms designed in the
 * following research paper. */
/* see: https://eprint.iacr.org/2023/794 */

#ifndef AREION_H
#define AREION_H

#include <cryptography-run/base.h>

#ifdef CR_HAS_AREION

#include "areion_hw.h"

#if defined(__cplusplus)
extern "C" {
#endif

static void perm_areion256_forward(u256_t *state) {
  perm256(state->native128[0], state->native128[1]);
}

static void perm_areion256_forward_x4(u256_t state[4]) {
  perm256x4(state[0].native128[0], state[0].native128[1], state[1].native128[0],
            state[1].native128[1], state[2].native128[0], state[2].native128[1],
            state[3].native128[0], state[3].native128[1]);
}

static void perm_areion256_forward_x8(u256_t state[8]) {
  perm256x8(state[0].native128[0], state[0].native128[1], state[1].native128[0],
            state[1].native128[1], state[2].native128[0], state[2].native128[1],
            state[3].native128[0], state[3].native128[1], state[4].native128[0],
            state[4].native128[1], state[5].native128[0], state[5].native128[1],
            state[6].native128[0], state[6].native128[1], state[7].native128[0],
            state[7].native128[1]);
}

static void perm_areion256_backward(u256_t *state) {
  Inv_perm256(state->native128[0], state->native128[1]);
}

static void perm_areion512_forward(u512_t *state) {
  perm512(state->native128[0], state->native128[1], state->native128[2],
          state->native128[3]);
}

static void perm_areion512_backward(u512_t *state) {
// XXX: only the x86 implementation has this
#ifdef __x86_64__
  Inv_perm512(state->native128[0], state->native128[1], state->native128[2],
              state->native128[3]);
#endif
}

static void perm_areion512_duplex_chunk(u256_t *rate, u256_t *cap) {
  perm512(rate->native128[0], rate->native128[1], cap->native128[0],
          cap->native128[1]);
}

#ifdef __cplusplus
}
#endif

#endif  // CR_HAS_AREION

#endif
