/*
 * Overwrite Duplex based on a 512-bit permutation
 *
 * :copyright: (c) 2025 by OCH authors.
 * :license: Creative Commons CC0 1.0
 */

#include "od512.h"

/* returns true if |ctx| is valid, and false otherwise */
static bool OD512_ctx_valid(OD512_ctx *ctx) {
  // rate_fill cannot be larger than the size of rate
  if (ctx->rate_fill >= 32) {
    return false;
  }
  // excess rate should be initialized to 0x00
  if (ctx->rate_fill > 0) {
    uint8_t excess[32] = {0};
    if (memcmp(ctx->rate.u8 + ctx->rate_fill, excess, (32 - ctx->rate_fill)) !=
        0) {
      return false;
    }
  }
  // once finalized, cannot update or finalize
  if (ctx->finalized == true) {
    return false;
  }
  return true;
}

static int OD512_init(OD512_DuplexChunk duplex_chunk,
                      HashState *hash_ctx,
                      const uint8_t *key,
                      size_t key_len,
                      size_t digest_len) {
  assert(key_len == OD512_key_len);
  assert(digest_len == OD512_digest_len);
  OD512_ctx *ctx = (OD512_ctx *)hash_ctx;
  ctx->rate = load256(key);
  ctx->capacity = zero256();
  ctx->duplex_chunk = duplex_chunk;
  ctx->duplex_chunk(&ctx->rate, &ctx->capacity);
  ctx->rate_fill = 0;
  ctx->rate = zero256();
  ctx->finalized = false;
  return 1;
}

static int OD512_init_keyless(OD512_DuplexChunk duplex_chunk,
                              HashState *hash_ctx,
                              size_t digest_len) {
  assert(digest_len == OD512_digest_len);
  OD512_ctx *ctx = (OD512_ctx *)hash_ctx;
  ctx->rate = zero256();
  ctx->capacity = zero256();
  ctx->duplex_chunk = duplex_chunk;
  ctx->duplex_chunk(&ctx->rate, &ctx->capacity);
  ctx->rate_fill = 0;
  ctx->rate = zero256();
  return 1;
}

static int OD512_update(HashState *hash_ctx, const uint8_t *in, size_t in_len) {
  OD512_ctx *ctx = (OD512_ctx *)hash_ctx;
  if (!OD512_ctx_valid(ctx)) {
    return 0;
  }

  if (in_len == 0) {
    /* do nothing */
    return 1;
  }

  int ret = 1;
  int in_idx = 0;

  /* 0. if less than a chunk, eat everything and update ctx->rate_fill */
  if ((ctx->rate_fill > 0) && ((ctx->rate_fill + in_len) < 32)) {
    memcpy(ctx->rate.u8 + ctx->rate_fill, in, in_len);
    ctx->rate_fill = (ctx->rate_fill + in_len);
    return ret;
  }

  /* 1. if there's unprocessed rate, try to eat to first chunk */
  if ((ctx->rate_fill > 0) && ((ctx->rate_fill + in_len) >= 32)) {
    memcpy(ctx->rate.u8 + ctx->rate_fill, in, 32 - ctx->rate_fill);
    ctx->duplex_chunk(&ctx->rate, &ctx->capacity);
    ctx->rate_fill = 0;
  }

  /* 2. now, eat in 32-byte blocks */
  if (ctx->rate_fill == 0) {
    for (; (in_idx + 32) <= in_len; in_idx += 32) {
      ctx->rate = load256(in + in_idx);
      ctx->duplex_chunk(&ctx->rate, &ctx->capacity);
    }
  }

  /* 3. finally, eat excess and update ctx->rate_fill */
  if (in_idx < in_len) {
    assert(ctx->rate_fill == 0);
    assert((in_len - in_idx) < 32);
    ctx->rate = zero256();
    memcpy(ctx->rate.u8, in + in_idx, (in_len - in_idx));
    ctx->rate_fill = in_len - in_idx;
  }

  return ret;
}

static int OD512_final(HashState *hash_ctx,
                       uint8_t *digest,
                       size_t digest_len) {
  assert(digest_len == OD512_digest_len);

  OD512_ctx *ctx = (OD512_ctx *)hash_ctx;
  if (!OD512_ctx_valid(ctx)) {
    return 0;
  }

  int ret = 1;

  /* 1. if there's any unprocessed rate, first eat that */
  if (ctx->rate_fill > 0) {
    ctx->duplex_chunk(&ctx->rate, &ctx->capacity);
    ctx->rate_fill = 0;
  }

  /* 2. now return the processed rate */
  assert(ctx->rate_fill == 0);
  store256(digest, ctx->rate);

  /* 3. set the finalized flag to prevent more updates and finalizes */
  ctx->finalized = true;

  return ret;
}

static int OD512_hash(OD512_DuplexChunk duplex_chunk,
                      uint8_t *digest,
                      size_t digest_len,
                      const uint8_t *msg,
                      size_t msg_len) {
  int ret = 1;
  HashState ctx;
  ret &= OD512_init_keyless(duplex_chunk, &ctx, digest_len);
  ret &= OD512_update(&ctx, msg, msg_len);
  ret &= OD512_final(&ctx, digest, digest_len);
  return ret;
}

static int OD512_keyed_hash(OD512_DuplexChunk duplex_chunk,
                            const uint8_t *key,
                            size_t key_len,
                            uint8_t *digest,
                            size_t digest_len,
                            const uint8_t *msg,
                            size_t msg_len) {
  int ret = 1;
  HashState ctx;
  ret &= OD512_init(duplex_chunk, &ctx, key, key_len, digest_len);
  ret &= OD512_update(&ctx, msg, msg_len);
  ret &= OD512_final(&ctx, digest, digest_len);
  return ret;
}

/* ------------------------------------------------------------------------- */
/* Hash interface for Areion512-Sponge                                       */

#ifdef CR_HAS_AREION
#include "../../perm/areion/areion.h"

static const OD512_DuplexChunk areion512_duplex_chunk =
    &perm_areion512_duplex_chunk;

static int ODAreion512_init(HashState *hash_ctx,
                            const uint8_t *key,
                            size_t key_len,
                            size_t digest_len) {
  return OD512_init(areion512_duplex_chunk, hash_ctx, key, key_len, digest_len);
}
static int ODAreion512_hash(uint8_t *digest,
                            size_t digest_len,
                            const uint8_t *msg,
                            size_t msg_len) {
  return OD512_hash(areion512_duplex_chunk, digest, digest_len, msg, msg_len);
}
static int ODAreion512_keyed_hash(const uint8_t *key,
                                  size_t key_len,
                                  uint8_t *digest,
                                  size_t digest_len,
                                  const uint8_t *msg,
                                  size_t msg_len) {
  return OD512_keyed_hash(areion512_duplex_chunk, key, key_len, digest,
                          digest_len, msg, msg_len);
}

static const Hash ODAreion512 = {"ODAreion512",          OD512_key_len,
                                 OD512_digest_len,       ODAreion512_hash,
                                 ODAreion512_keyed_hash, ODAreion512_init,
                                 OD512_update,           OD512_final};

const Hash *Hash_ODAreion512() {
  return &ODAreion512;
}

#endif