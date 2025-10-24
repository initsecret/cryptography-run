/* Adapted from
 * https://github.com/google/hctr2/blob/fac589e7b88622bda42fb0b9ab3192803363987f/benchmark/src/polyval.h
 */

// FIXME: remove this file

/*
 * Copyright 2021 Google LLC
 *
 * Use of this source code is governed by an MIT-style
 * license that can be found in the LICENSE file or at
 * https://opensource.org/licenses/MIT.
 */

// FIXME: make this use the hash API.

#ifndef CR_AXU_H
#define CR_AXU_H

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define POLYVAL_BLOCK_SIZE 16
#define POLYVAL_DIGEST_SIZE 16
#define POLYVAL_KEY_SIZE 16
#define NUM_KEY_POWERS 8

typedef struct {
  /*
   * Array of montgomery-form GF(2^128) field elements
   * stored in big-little endian.
   *
   * The GF(2^128) element x^128 is represented in memory as
   * [0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00 |
   *  0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x80 ]
   * The GF(2^128) element 1 is represented in memory as
   * [0x01 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00 |
   *  0x00 0x00 0x00 0x00 | 0x00 0x00 0x00 0x00 ]
   *
   * The array contains the GF(2^128) elements h^n .. h^1
   * in decreasing order of degree.
   */
  alignas(32) uint8_t powers[NUM_KEY_POWERS][POLYVAL_BLOCK_SIZE];
} PolyvalKey;

typedef struct {
  alignas(8) uint8_t state[POLYVAL_BLOCK_SIZE];
} PolyvalState;

// FIXME: rewrite these functions to return 0 and 1

void polyval_setkey(PolyvalKey *key, const uint8_t raw_key[POLYVAL_KEY_SIZE]);

void polyval_init(PolyvalState *state);
void polyval_update(PolyvalState *state,
                    const PolyvalKey *key,
                    const uint8_t *in,
                    size_t nblocks);
void polyval_emit(PolyvalState *state, uint8_t out[POLYVAL_DIGEST_SIZE]);

void polyval_key_oneshot(PolyvalKey *key,
                         const uint8_t *in,
                         size_t nblocks,
                         uint8_t out[POLYVAL_DIGEST_SIZE]);

void polyval_oneshot(const uint8_t raw_key[POLYVAL_KEY_SIZE],
                     const uint8_t *in,
                     size_t nblocks,
                     uint8_t out[POLYVAL_DIGEST_SIZE]);

/*
 * POLYVAL x2
 */

typedef struct {
  alignas(32) PolyvalKey key0;
  alignas(32) PolyvalKey key1;
} PolyvalX2Key;

typedef struct {
  alignas(8) PolyvalState state0;
  alignas(8) PolyvalState state1;
} PolyvalX2State;

#define POLYVAL_X2_DIGEST_SIZE 32
#define POLYVAL_X2_KEY_SIZE 32
#define POLYVAL_X2_BLOCK_SIZE 16

void polyval_x2_setkey(PolyvalX2Key *key,
                       const uint8_t raw_key[POLYVAL_X2_KEY_SIZE]);

void polyval_x2_init(PolyvalX2State *state);
void polyval_x2_update(PolyvalX2State *state,
                       const PolyvalX2Key *key,
                       const uint8_t *in,
                       size_t nblocks);
void polyval_x2_emit(PolyvalX2State *state,
                     uint8_t out[POLYVAL_X2_DIGEST_SIZE]);

void polyval_x2_key_oneshot(PolyvalX2Key *key,
                            const uint8_t *in,
                            size_t nblocks,
                            uint8_t out[POLYVAL_X2_DIGEST_SIZE]);

void polyval_x2_oneshot(const uint8_t raw_key[POLYVAL_X2_KEY_SIZE],
                        const uint8_t *in,
                        size_t nblocks,
                        uint8_t out[POLYVAL_X2_DIGEST_SIZE]);

#ifdef __cplusplus
}
#endif

#endif  // CR_AXU_H