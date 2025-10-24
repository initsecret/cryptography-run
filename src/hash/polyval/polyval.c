/*
 * Polyval, as specified in
 * https://www.rfc-editor.org/rfc/rfc8452.html#section-3
 */

#include <assert.h>

#include <cryptography-run/base.h>

#include <cryptography-run/axuhash.h>
#include <cryptography-run/gf128.h>

#include "polyval_internal.h"

static const uint8_t Polyval_key_len = 16;
static const uint8_t Polyval_digest_len = 16;

static const uint8_t X2Polyval_key_len = 32;
static const uint8_t X2Polyval_digest_len = 32;

/* ------------------------------------------------------------------------- */
/* Polyval internal functions                                                */

// Number of H powers to precompute
#ifdef __x86_64__
#define H_TABLE_SIZE 8
#else
#define H_TABLE_SIZE 1
#endif

// modulus: x^128 + x^127 + x^126 + x^121 + 1
typedef struct {
  // Array of H powers in decreasing order
  //   H = H^(H_TABLE_SIZE)
  //   Htable[i] = H^(H_TABLE_SIZE - i)
  //   Htable[H_TABLE_SIZE - 1] = H^1
  u128_t Htable[H_TABLE_SIZE];
} PolyvalKey;

typedef u128_t PolyvalState;

#ifdef __x86_64__
// From
// https://github.com/google/hctr2/blob/fac589e7b88622bda42fb0b9ab3192803363987f/benchmark/src/polyval.c#L12-L17
void clmul_polyval_update(const PolyvalKey *key,
                          const uint8_t *in,
                          size_t nblocks,
                          uint8_t *accumulator);
void clmul_polyval_mul(uint8_t *op1, const uint8_t *op2);
#endif

/**
 * computes
 *   dot(a,b) = a * b * x^{-128} mod x^128 + x^127 + x^126 + x^121 + 1
 * and stores the result to a.
 *
 * dot is defined in https://www.rfc-editor.org/rfc/rfc8452.html#section-3
 */
void gf128_dot(u128_t *a, const u128_t *b) {
#ifdef __x86_64__
  clmul_polyval_mul(a->u8, b->u8);
#else
  gfmul_int(a->u64, b->u64, a->u64);
#endif
}

/**
 * initializes a polyval key by precomputing powers
 * adapted from
 * https://github.com/google/hctr2/blob/fac589e7b88622bda42fb0b9ab3192803363987f/benchmark/src/polyval.c#L49-L60
 */
static void _polyval_key_init(PolyvalKey *key,
                              const uint8_t *raw_key,
                              size_t raw_key_len) {
  assert(raw_key_len == 16);
  u128_t H = load128(raw_key);

  // fill table in reverse order
  key->Htable[H_TABLE_SIZE - 1] = H;
  for (int i = H_TABLE_SIZE - 2; i >= 0; i--) {
    key->Htable[i] = H;
    gf128_dot(&key->Htable[i], &key->Htable[i + 1]);
  }
}

/**
 * suppose |in| is (X_1,...,X_n), where X_i is 16 bytes and n = |in_blocklen|.
 *
 * then, this function computes S_n where
 *  S_0 = |state|
 *  S_i = dot(S_{j-1} + X_j, H)
 *
 * stores the result to |state|.
 */
static void _polyval_update(PolyvalState *state,
                            const PolyvalKey *key,
                            const uint8_t *in,
                            size_t in_blocklen) {
#ifdef __x86_64__
  clmul_polyval_update(key, in, in_blocklen, state->u8);
#else
  for (int i = 0; i < in_blocklen; i++) {
    *state = xor128(*state, load128(in + 16 * i));
    gf128_dot(state, &key->Htable[H_TABLE_SIZE - 1]);
  }
#endif
}

/**
 * writes |state| to |digest|
 */
static void _polyval_final(const PolyvalState *state,
                           uint8_t *digest,
                           size_t digest_len) {
  assert(digest_len == 16);
  memcpy(digest, state->u8, 16);
}

/* ------------------------------------------------------------------------- */
/* AxuHash interface for Polyval                                             */

static int Polyval_init(AxuHashKey *axu_key,
                        const uint8_t *key,
                        size_t key_len,
                        size_t digest_len) {
  if ((key_len != Polyval_key_len) || (digest_len != Polyval_digest_len)) {
    return 0;
  }
  PolyvalKey *polyval_key = (PolyvalKey *)axu_key;
  _polyval_key_init(polyval_key, key, key_len);
  return 1;
}

static int Polyval_update_and_final(const AxuHashKey *axu_key,
                                    uint8_t *digest,
                                    size_t digest_len,
                                    const uint8_t *in,
                                    size_t in_len) {
  if (digest_len != Polyval_digest_len) {
    return 0;
  }
  if ((in_len % 16) != 0) {
    return 0;
  }
  size_t in_blocklen = in_len / 16;
  PolyvalKey *polyval_key = (PolyvalKey *)axu_key;

  PolyvalState state = zero128();
  _polyval_update(&state, polyval_key, in, in_blocklen);
  _polyval_final(&state, digest, digest_len);

  return 1;
}

static const AxuHash polyval = {"Polyval", Polyval_key_len, Polyval_digest_len,
                                Polyval_init, Polyval_update_and_final};

const AxuHash *AxuHash_Polyval() {
  return &polyval;
}

/* ------------------------------------------------------------------------- */
/* AxuHash interface for X2Polyval                                           */

typedef struct {
  PolyvalKey key0;
  PolyvalKey key1;
} X2PolyvalKey;

typedef struct {
  PolyvalState state0;
  PolyvalState state1;
} X2PolyvalState;

static int X2Polyval_init(AxuHashKey *axu_key,
                          const uint8_t *key,
                          size_t key_len,
                          size_t digest_len) {
  if ((key_len != X2Polyval_key_len) || (digest_len != X2Polyval_digest_len)) {
    return 0;
  }
  X2PolyvalKey *polyval_key = (X2PolyvalKey *)axu_key;
  assert(key_len == 32);
  _polyval_key_init(&polyval_key->key0, key, 16);
  _polyval_key_init(&polyval_key->key0, key + 16, 16);
  return 1;
}

static int X2Polyval_update_and_final(const AxuHashKey *axu_key,
                                      uint8_t *digest,
                                      size_t digest_len,
                                      const uint8_t *in,
                                      size_t in_len) {
  if (digest_len != X2Polyval_digest_len) {
    return 0;
  }
  if ((in_len % 16) != 0) {
    return 0;
  }
  size_t in_blocklen = in_len / 16;
  X2PolyvalKey *polyval_key = (X2PolyvalKey *)axu_key;

  PolyvalState state0 = zero128();
  PolyvalState state1 = zero128();
  _polyval_update(&state0, &polyval_key->key0, in, in_blocklen);
  _polyval_update(&state1, &polyval_key->key1, in, in_blocklen);
  assert(digest_len == 32);
  _polyval_final(&state0, digest, 16);
  _polyval_final(&state1, digest + 16, 16);
  return 1;
}

static const AxuHash x2polyval = {"X2Polyval", X2Polyval_key_len,
                                  X2Polyval_digest_len, X2Polyval_init,
                                  X2Polyval_update_and_final};

const AxuHash *AxuHash_X2Polyval() {
  return &x2polyval;
}
