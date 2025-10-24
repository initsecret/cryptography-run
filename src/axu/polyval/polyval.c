/* Adapted from
 * https://github.com/google/hctr2/blob/fac589e7b88622bda42fb0b9ab3192803363987f/benchmark/src/polyval.c
 */

/*
 * Copyright 2021 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

#include <cryptography-run/axu.h>
#include "../../internal.h"

#ifdef __x86_64__
void clmul_polyval_update(const PolyvalKey *key,
                          const uint8_t *in,
                          size_t nblocks,
                          uint8_t *accumulator);
void clmul_polyval_mul(uint8_t *op1, const uint8_t *op2);
#define POLYVAL_UPDATE clmul_polyval_update
#define MUL clmul_polyval_mul
#elif defined(__aarch64__)
void pmull_polyval_update(const PolyvalKey *key,
                          const uint8_t *in,
                          size_t nblocks,
                          uint8_t *accumulator);
void pmull_polyval_mul(uint8_t *op1, const uint8_t *op2);
#define POLYVAL_UPDATE pmull_polyval_update
#define MUL pmull_polyval_mul
#else
#error Unsupported architecture.
#endif

void polyval_init(PolyvalState *state) {
  zeroize(state, sizeof(PolyvalState));
}

void polyval_setkey(PolyvalKey *key, const uint8_t raw_key[POLYVAL_KEY_SIZE]) {
  /* set h */
  memcpy(&key->powers[NUM_KEY_POWERS - 1], raw_key, POLYVAL_BLOCK_SIZE);

  /* Precompute key powers */
  for (int i = NUM_KEY_POWERS - 2; i >= 0; i--) {
    memcpy(&key->powers[i], raw_key, POLYVAL_BLOCK_SIZE);
    MUL(key->powers[i], key->powers[i + 1]);
  }
}

/*
 * If the message is not a multiple of 16 bytes, the last block should be
 * padded and passed as final_block. This allows callers of polyval to use
 * their own padding method without paying any additional performance cost.
 */
void polyval_update(PolyvalState *state,
                    const PolyvalKey *key,
                    const uint8_t *in,
                    size_t nblocks) {
  POLYVAL_UPDATE(key, in, nblocks, state->state);
}

void polyval_emit(PolyvalState *state, uint8_t out[POLYVAL_DIGEST_SIZE]) {
  memcpy(out, &state->state, POLYVAL_DIGEST_SIZE);
}

void polyval_key_oneshot(PolyvalKey *key,
                         const uint8_t *in,
                         size_t nblocks,
                         uint8_t out[POLYVAL_DIGEST_SIZE]) {
  PolyvalState state;
  polyval_init(&state);
  polyval_update(&state, key, in, nblocks);
  polyval_emit(&state, out);
}

void polyval_oneshot(const uint8_t raw_key[POLYVAL_KEY_SIZE],
                     const uint8_t *in,
                     size_t nblocks,
                     uint8_t out[POLYVAL_DIGEST_SIZE]) {
  PolyvalKey key;
  PolyvalState state;
  polyval_setkey(&key, raw_key);
  polyval_init(&state);
  polyval_update(&state, &key, in, nblocks);
  polyval_emit(&state, out);
}

void polyval_x2_setkey(PolyvalX2Key *key,
                       const uint8_t raw_key[POLYVAL_X2_KEY_SIZE]) {
  polyval_setkey(&key->key0, raw_key);
  polyval_setkey(&key->key1, raw_key + POLYVAL_KEY_SIZE);
}

void polyval_x2_init(PolyvalX2State *state) {
  polyval_init(&state->state0);
  polyval_init(&state->state1);
}

void polyval_x2_update(PolyvalX2State *state,
                       const PolyvalX2Key *key,
                       const uint8_t *in,
                       size_t nblocks) {
  polyval_update(&state->state0, &key->key0, in, nblocks);
  polyval_update(&state->state1, &key->key1, in, nblocks);
}

void polyval_x2_emit(PolyvalX2State *state,
                     uint8_t out[POLYVAL_X2_DIGEST_SIZE]) {
  polyval_emit(&state->state0, out);
  polyval_emit(&state->state1, out + POLYVAL_DIGEST_SIZE);
}

void polyval_x2_key_oneshot(PolyvalX2Key *key,
                            const uint8_t *in,
                            size_t nblocks,
                            uint8_t out[POLYVAL_X2_DIGEST_SIZE]) {
  polyval_key_oneshot(&key->key0, in, nblocks, out);
  polyval_key_oneshot(&key->key1, in, nblocks, out + POLYVAL_DIGEST_SIZE);
}

void polyval_x2_oneshot(const uint8_t raw_key[POLYVAL_X2_KEY_SIZE],
                        const uint8_t *in,
                        size_t nblocks,
                        uint8_t out[POLYVAL_X2_DIGEST_SIZE]) {
  polyval_oneshot(raw_key, in, nblocks, out);
  polyval_oneshot(raw_key + POLYVAL_KEY_SIZE, in, nblocks,
                  out + POLYVAL_DIGEST_SIZE);
}
