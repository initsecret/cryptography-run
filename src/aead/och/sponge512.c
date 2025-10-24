/*
 * Sponge based on a 512-bit permutation
 *
 * :copyright: (c) 2025 by OCH authors.
 * :license: Creative Commons CC0 1.0
 */

#include <assert.h>

#include <cryptography-run/aead.h>
#include <cryptography-run/axu.h>
#include <cryptography-run/gf256.h>
#include <cryptography-run/hash.h>
#include <cryptography-run/perm.h>

/** API for permuting a 512-bit sponge state forward */
typedef void (*Sponge512_forward)(u512_t *inout);

static const uint8_t Sponge512_key_len = 32;
static const uint8_t Sponge512_digest_len = 32;

static const uint8_t label_init_with_key = 0xd0;
static const uint8_t label_init_keyless = 0xd1;

// Sponge512
//  Permutation width = 512 bits
//  Rate = 256 bits
//  Capacity = 256 bits
typedef struct {
  u512_t state;
  Sponge512_forward forward;
} sponge512_ctx;

static int Sponge512_init(Sponge512_forward perm_forward,
                          HashState *hash_ctx,
                          const uint8_t *key,
                          size_t key_len,
                          size_t digest_len) {
  assert(key_len == Sponge512_key_len);
  sponge512_ctx *ctx = (sponge512_ctx *)hash_ctx;
  ctx->state.u256[0] = load256(key);
  ctx->state.u256[1] = zero256();
  ctx->state.u256[1].u8[0] = label_init_with_key;
  ctx->forward = perm_forward;
  ctx->forward(&ctx->state);
  return 1;
}

static int Sponge512_init_keyless(Sponge512_forward perm_forward,
                                  HashState *hash_ctx,
                                  size_t digest_len) {
  sponge512_ctx *ctx = (sponge512_ctx *)hash_ctx;
  ctx->state.u256[0] = zero256();
  ctx->state.u256[1] = zero256();
  ctx->state.u256[1].u8[0] = label_init_keyless;
  ctx->forward = perm_forward;
  ctx->forward(&ctx->state);
  return 1;
}

/**
 * @brief eats a 32 byte chunk and updates the state
 *
 * @param ctx
 * @param chunk MUST be uint8_t[32]
 * @return int 1 on success and 0 otherwise.
 */
static int Sponge512_update_chunk(sponge512_ctx *ctx, const uint8_t *chunk) {
  ctx->state.u256[0] = xor256(load256(chunk), ctx->state.u256[0]);
  ctx->forward(&ctx->state);
  return 1;
}

static int Sponge512_update(HashState *hash_ctx,
                            const uint8_t *in,
                            size_t in_len) {
  sponge512_ctx *ctx = (sponge512_ctx *)hash_ctx;
  int ret = 1;

  // first eat 32-byte chunks
  int in_idx = 0;
  for (; (in_idx + 32) <= in_len; in_idx += 32) {
    ret &= Sponge512_update_chunk(ctx, in + in_idx);
  }
  // now eat excess
  if (in_idx < in_len) {
    assert((in_len - in_idx) < 32);
    uint8_t excess[32] = {0};
    int excess_idx = 0;
    for (; excess_idx < (in_len - in_idx); excess_idx += 1) {
      excess[excess_idx] = in[in_idx + excess_idx];
    }
    assert(in_len == (in_idx + excess_idx));
    assert(excess_idx < 32);
    excess[excess_idx] = 0xff;
    ret &= Sponge512_update_chunk(ctx, excess);
  }
  return ret;
}

static int Sponge512_final(HashState *hash_ctx,
                           uint8_t *digest,
                           size_t digest_len) {
  sponge512_ctx *ctx = (sponge512_ctx *)hash_ctx;
  if (digest_len == 32) {
    ctx->forward(&ctx->state);
    store256(digest, ctx->state.u256[0]);
    return 1;
  } else if (digest_len == 64) {
    ctx->forward(&ctx->state);
    store256(digest, ctx->state.u256[0]);
    ctx->forward(&ctx->state);
    store256(digest, ctx->state.u256[0]);
    return 1;
  }
  // Unsupported digest lengths
  assert(false);
  return 0;
}

static int Sponge512_hash(Sponge512_forward perm_forward,
                          uint8_t *digest,
                          size_t digest_len,
                          const uint8_t *msg,
                          size_t msg_len) {
  int ret = 1;
  HashState ctx;
  ret &= Sponge512_init_keyless(perm_forward, &ctx, digest_len);
  ret &= Sponge512_update(&ctx, msg, msg_len);
  ret &= Sponge512_final(&ctx, digest, digest_len);
  return ret;
}

static int Sponge512_keyed_hash(Sponge512_forward perm_forward,
                                const uint8_t *key,
                                size_t key_len,
                                uint8_t *digest,
                                size_t digest_len,
                                const uint8_t *msg,
                                size_t msg_len) {
  int ret = 1;
  HashState ctx;
  ret &= Sponge512_init(perm_forward, &ctx, key, key_len, digest_len);
  ret &= Sponge512_update(&ctx, msg, msg_len);
  ret &= Sponge512_final(&ctx, digest, digest_len);
  return ret;
}

/* ------------------------------------------------------------------------- */
/* Hash interface for Sparkle512-Sponge                                      */

#include "../../perm/sparkle/sparkle.h"

static void Sparkle512_forward(u512_t *inout) {
  perm_sparkle512big_forward(inout);
}

static int Sparkle512_Sponge512_init(HashState *hash_ctx,
                                     const uint8_t *key,
                                     size_t key_len,
                                     size_t digest_len) {
  return Sponge512_init(Sparkle512_forward, hash_ctx, key, key_len, digest_len);
}
static int Sparkle512_Sponge512_hash(uint8_t *digest,
                                     size_t digest_len,
                                     const uint8_t *msg,
                                     size_t msg_len) {
  return Sponge512_hash(Sparkle512_forward, digest, digest_len, msg, msg_len);
}
static int Sparkle512_Sponge512_keyed_hash(const uint8_t *key,
                                           size_t key_len,
                                           uint8_t *digest,
                                           size_t digest_len,
                                           const uint8_t *msg,
                                           size_t msg_len) {
  return Sponge512_keyed_hash(Sparkle512_forward, key, key_len, digest,
                              digest_len, msg, msg_len);
}

static const Hash sparkle512sponge = {"Sparkle512-Sponge",
                                      Sponge512_key_len,
                                      Sponge512_digest_len,
                                      Sparkle512_Sponge512_hash,
                                      Sparkle512_Sponge512_keyed_hash,
                                      Sparkle512_Sponge512_init,
                                      Sponge512_update,
                                      Sponge512_final};

const Hash *Hash_Sparkle512Sponge() {
  return &sparkle512sponge;
}

/* ------------------------------------------------------------------------- */
/* Hash interface for Areion512-Sponge                                       */

#ifdef CR_HAS_AREION
#include "../../perm/areion/areion.h"

static void Areion512_forward(u512_t *inout) {
  perm_areion512_forward(inout);
}

static int Areion512_Sponge512_init(HashState *hash_ctx,
                                    const uint8_t *key,
                                    size_t key_len,
                                    size_t digest_len) {
  return Sponge512_init(Areion512_forward, hash_ctx, key, key_len, digest_len);
}
static int Areion512_Sponge512_hash(uint8_t *digest,
                                    size_t digest_len,
                                    const uint8_t *msg,
                                    size_t msg_len) {
  return Sponge512_hash(Areion512_forward, digest, digest_len, msg, msg_len);
}
static int Areion512_Sponge512_keyed_hash(const uint8_t *key,
                                          size_t key_len,
                                          uint8_t *digest,
                                          size_t digest_len,
                                          const uint8_t *msg,
                                          size_t msg_len) {
  return Sponge512_keyed_hash(Areion512_forward, key, key_len, digest,
                              digest_len, msg, msg_len);
}

static const Hash areion512sponge = {"Areion512-Sponge",
                                     Sponge512_key_len,
                                     Sponge512_digest_len,
                                     Areion512_Sponge512_hash,
                                     Areion512_Sponge512_keyed_hash,
                                     Areion512_Sponge512_init,
                                     Sponge512_update,
                                     Sponge512_final};

const Hash *Hash_Areion512Sponge() {
  return &areion512sponge;
}

#endif