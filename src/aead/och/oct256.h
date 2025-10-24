/*
    Instantiations of OCT with a 256-bit permutation

    :copyright: (c) 2025 by OCH authors.
    :license: Creative Commons CC0 1.0
*/

#ifndef CR_OCT256_H
#define CR_OCT256_H

#include <assert.h>
#include <stdalign.h>

#include <cryptography-run/base.h>
#include <cryptography-run/gf256.h>

#include <cryptography-run/aead.h>

#include "em256.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef u256_t block;

typedef u256_t OctKey;
typedef u256_t OctOffset;

// Size of OCT256 offset table to precompute
#define L_TABLE_SIZE 16

/**
 * Oct256State represents the internal state of OCT256.
 * Aligned to 32 byte boundary.
 */
typedef struct {
  // 256-bit OCT key
  alignas(32) OctKey tbc_key;
  // precomputed key-based OCT offsets
  alignas(32) OctOffset Lstar;
  alignas(32) OctOffset Ldollar;
  alignas(32) OctOffset L[L_TABLE_SIZE];
  // cached key and nonce-based OCT offsets
  alignas(32) u256_t cached_Top;
  alignas(32) OctOffset cached_KTop;
} Oct256State;

/**
 * Initalizes OCT256State |oct_ctx| with |key|.
 *
 * |key| MUST be supported length.
 *
 * @return one on success and zero otherwise.
 */
static int Oct256_setup(const EM256 *oct,
                        Oct256State *ctx,
                        const uint8_t *key,
                        size_t key_len) {
  assert(key_len == 32);
  // XXX: is this faster using a temp variable instead of ctx-> values?
  // Compute key-dependent OCT offsets
  ctx->Lstar = zero256();
  oct->EM_encrypt(ctx->tbc_key, &ctx->Lstar);
  ctx->Ldollar = gf256_double(ctx->Lstar);
  ctx->L[0] = gf256_double(ctx->Ldollar);
  for (int i = 1; i < L_TABLE_SIZE; i++) {
    ctx->L[i] = gf256_double(ctx->L[i - 1]);
  }
  // Initialize the cache for an all-zero Top
  u256_t Top = zero256();
  u256_t KTop = Top;
  oct->EM_encrypt(ctx->tbc_key, &KTop);
  ctx->cached_Top = Top;
  ctx->cached_KTop = KTop;
  assert(equal256(ctx->cached_KTop, zero256()) == false);
  return 1;
}

/**
 * Computes the initial offset for OCT using a 256-bit |N| value.
 *
 * May update the cached Top and KTop values in |oct_ctx|.
 *
 * @return initial offset
 */
static OctOffset _init_offset(const EM256 *oct,
                              Oct256State *oct_ctx,
                              const u256_t N) {
  // Based on gen_offset_from_nonce in Ted Krovetz's OCB3 implementation:
  // https://www.cs.ucdavis.edu/~rogaway/ocb/news/

  // split nonce into Top and Bottom
  // -------------------------------
  // get the low six bits of the nonce
  uint8_t Bottom = N.u8[31] & 0b00111111;
  u256_t Top = N;
  // set the low six bits to zero
  Top.u8[31] = Top.u8[31] & 0b11000000;
  // set the top zero bit to 1
  // FIXME: this is unnecessary, and OCB3 doesn't do it, so remove in paper
  // Top.u8[31] = Top.u8[31] | 0b00100000;

  // compute KTop
  // ------------
  u256_t KTop = zero256();
  // use cached value if possible
  if (equal256(oct_ctx->cached_Top, Top)) {
    KTop = oct_ctx->cached_KTop;
  } else {
    // compute KTop
    KTop = Top;
    oct->EM_encrypt(oct_ctx->tbc_key, &KTop);
    // update cache
    oct_ctx->cached_Top = Top;
    oct_ctx->cached_KTop = KTop;
  }

  // compute RN
  // ----------
  // RN = (KTop << bottom)[0:256]
  u256_t RN = shiftleft256(KTop, Bottom);
  return RN;
}

/**
 * Computes n0_offset: the initial offset for OCT based on the public nonce.
 */
static OctOffset Oct256_init_n0_offset(const EM256 *oct,
                                       Oct256State *oct_ctx,
                                       const uint8_t *public_nonce,
                                       size_t public_nonce_len,
                                       size_t secret_nonce_len) {
  if ((public_nonce_len == 0) && (secret_nonce_len == 32)) {
    // N0 = public_nonce || 0^* = all-zeros
    u256_t N0 = zero256();
    return _init_offset(oct, oct_ctx, N0);
  } else if ((public_nonce_len == 32) && (secret_nonce_len == 0)) {
    // N0 = public_nonce || 0^* = public_nonce
    u256_t N0 = load256(public_nonce);
    return _init_offset(oct, oct_ctx, N0);
  } else {
    // unimplemented
    assert(false);
    return zero256();
  }
}

/**
 * Computes n_offset: the initial offset for OCT based on the public nonce and
 * the secret nonce.
 */
static OctOffset Oct256_init_n_offset(const EM256 *oct,
                                      Oct256State *oct_ctx,
                                      const uint8_t *public_nonce,
                                      size_t public_nonce_len,
                                      const uint8_t *secret_nonce,
                                      size_t secret_nonce_len) {
  if ((public_nonce_len == 0) && (secret_nonce_len == 32)) {
    // N  = public_nonce || secret_nonce = secret_nonce
    u256_t N = load256(secret_nonce);
    return _init_offset(oct, oct_ctx, N);
  } else if ((public_nonce_len == 32) && (secret_nonce_len == 0)) {
    // N  = public_nonce || secret_nonce = public_nonce
    u256_t N = load256(public_nonce);
    return _init_offset(oct, oct_ctx, N);
  } else {
    // unimplemented
    assert(false);
    return zero256();
  }
}

#ifdef __cplusplus
}
#endif

#endif  // CR_OCT256_H