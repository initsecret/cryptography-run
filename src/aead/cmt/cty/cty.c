
#include <assert.h>

#include <cryptography-run/aead.h>
#include <cryptography-run/hash.h>
#include <string.h>
#include "../../../internal.h"

#define CTY_INNER_TAG_LEN 32
#define CTY_OUTER_TAG_LEN 32
#define CTY_KEY_LEN 32
#define CTY_NONCE_LEN 32

static int cty_hash(const Hash *hash,
                    uint8_t *digest,
                    const uint8_t *key,
                    const uint8_t *nonce,
                    const uint8_t *ad,
                    size_t ad_len,
                    uint8_t inner_tag[CTY_INNER_TAG_LEN]) {
  int ret = 1;
  HashState hash_ctx;
  ret &= hash->init(&hash_ctx, key, CTY_KEY_LEN, CTY_OUTER_TAG_LEN);
  ret &= hash->update(&hash_ctx, nonce, CTY_NONCE_LEN);
  ret &= hash->update(&hash_ctx, ad, ad_len);
  ret &= hash->update(&hash_ctx, inner_tag, CTY_INNER_TAG_LEN);
  ret &= hash->final(&hash_ctx, digest, CTY_OUTER_TAG_LEN);
  return ret;
}

// FIXME: write this abstractly in terms of an Aead* and Hash*

/* ------------------------------------------------------------------------- */
/* Aead interface for CTY[Blake2b, Blake2b-OPP-MEM]                          */

static const uint8_t aead_cty_blake2b_opp_mem_key_len = CTY_KEY_LEN;
static const uint8_t aead_cty_blake2b_opp_mem_nonce_len = CTY_NONCE_LEN;
static const uint8_t aead_cty_blake2b_opp_mem_overhead = CTY_OUTER_TAG_LEN;

typedef struct {
  alignas(8) uint8_t blake2b_opp_mem_ctx[32];
  // need a copy of the key since blake2b currently does not support resetting
  // state
  alignas(8) uint8_t key[32];
} cty_blake2b_opp_mem_ctx;

int aead_cty_blake2b_opp_mem_init(AeadKey *aead_key,
                                  const uint8_t *key,
                                  size_t key_len) {
  int ret = 1;
  cty_blake2b_opp_mem_ctx *ctx = (cty_blake2b_opp_mem_ctx *)aead_key;
  // init aead and hash with the same key
  assert(key_len == aead_cty_blake2b_opp_mem_key_len);
  ret &= Aead_blake2b_opp_mem()->init((AeadKey *)ctx->blake2b_opp_mem_ctx, key,
                                      key_len);
  memcpy(ctx->key, key, aead_cty_blake2b_opp_mem_key_len);
  return ret;
}

int aead_cty_blake2b_opp_mem_seal(AeadKey *aead_key,
                                  uint8_t *ct,
                                  const uint8_t *msg,
                                  size_t msg_len,
                                  const uint8_t *ad,
                                  size_t ad_len,
                                  const uint8_t *nonce) {
  int ret = 1;
  cty_blake2b_opp_mem_ctx *ctx = (cty_blake2b_opp_mem_ctx *)aead_key;

  // encrypt with no ad to ct and inner_tag
  uint8_t inner_tag[CTY_INNER_TAG_LEN] = {0};
  ret &= Aead_blake2b_opp_mem()->seal_scatter(
      (AeadKey *)ctx->blake2b_opp_mem_ctx, ct, inner_tag, msg, msg_len, NULL, 0,
      nonce);

  // hash to tag
  cty_hash(Hash_blake2b(), ct + msg_len, ctx->key, nonce, ad, ad_len,
           inner_tag);

  return ret;
}

int aead_cty_blake2b_opp_mem_open(AeadKey *aead_key,
                                  uint8_t *msg,
                                  const uint8_t *ct,
                                  size_t ct_len,
                                  const uint8_t *ad,
                                  size_t ad_len,
                                  const uint8_t *nonce) {
  int ret = 1;
  cty_blake2b_opp_mem_ctx *ctx = (cty_blake2b_opp_mem_ctx *)aead_key;

  // partial decrypt with no ad to msg and inner_tag
  uint8_t inner_tag[CTY_INNER_TAG_LEN] = {0};
  ret &= Aead_blake2b_opp_mem()->partial_open(
      (AeadKey *)ctx->blake2b_opp_mem_ctx, msg, inner_tag, ct, ct_len, NULL, 0,
      nonce);

  // hash to tag and compare
  uint8_t expected_tag[CTY_OUTER_TAG_LEN] = {0};
  ret &= cty_hash(Hash_blake2b(), expected_tag, ctx->key, nonce, ad, ad_len,
                  inner_tag);
  ret &= constant_time_compare(expected_tag, ct + ct_len - CTY_OUTER_TAG_LEN,
                               CTY_OUTER_TAG_LEN);
  return ret;
}

static const Aead cty_blake2b_opp_mem = {"CTY[Blake2b, Blake2b-OPP-MEM]",
                                         aead_cty_blake2b_opp_mem_key_len,
                                         aead_cty_blake2b_opp_mem_nonce_len,
                                         aead_cty_blake2b_opp_mem_overhead,
                                         aead_cty_blake2b_opp_mem_init,
                                         aead_cty_blake2b_opp_mem_seal,
                                         aead_cty_blake2b_opp_mem_open,
                                         NULL,
                                         NULL};

const Aead *Aead_cty_blake2b_opp_mem() {
  return &cty_blake2b_opp_mem;
}

/* ------------------------------------------------------------------------- */
/* Aead interface for CTY[SHA256, Blake2b-OPP-MEM]                          */

static const uint8_t aead_cty_sha256_opp_mem_key_len = CTY_KEY_LEN;
static const uint8_t aead_cty_sha256_opp_mem_nonce_len = CTY_NONCE_LEN;
static const uint8_t aead_cty_sha256_opp_mem_overhead = CTY_OUTER_TAG_LEN;

typedef struct {
  alignas(8) uint8_t sha256_opp_mem_ctx[32];
  // need a copy of the key since sha256 currently does not support resetting
  // state
  alignas(8) uint8_t key[32];
} cty_sha256_opp_mem_ctx;

int aead_cty_sha256_opp_mem_init(AeadKey *aead_key,
                                 const uint8_t *key,
                                 size_t key_len) {
  int ret = 1;
  cty_sha256_opp_mem_ctx *ctx = (cty_sha256_opp_mem_ctx *)aead_key;
  // init aead and hash with the same key
  assert(key_len == aead_cty_sha256_opp_mem_key_len);
  ret &= Aead_blake2b_opp_mem()->init((AeadKey *)ctx->sha256_opp_mem_ctx, key,
                                      key_len);
  memcpy(ctx->key, key, aead_cty_sha256_opp_mem_key_len);
  return ret;
}

int aead_cty_sha256_opp_mem_seal(AeadKey *aead_key,
                                 uint8_t *ct,
                                 const uint8_t *msg,
                                 size_t msg_len,
                                 const uint8_t *ad,
                                 size_t ad_len,
                                 const uint8_t *nonce) {
  int ret = 1;
  cty_sha256_opp_mem_ctx *ctx = (cty_sha256_opp_mem_ctx *)aead_key;

  // encrypt with no ad to ct and inner_tag
  uint8_t inner_tag[CTY_INNER_TAG_LEN] = {0};
  ret &= Aead_blake2b_opp_mem()->seal_scatter(
      (AeadKey *)ctx->sha256_opp_mem_ctx, ct, inner_tag, msg, msg_len, NULL, 0,
      nonce);

  // hash to tag
  cty_hash(Hash_sha256(), ct + msg_len, ctx->key, nonce, ad, ad_len, inner_tag);

  return ret;
}

int aead_cty_sha256_opp_mem_open(AeadKey *aead_key,
                                 uint8_t *msg,
                                 const uint8_t *ct,
                                 size_t ct_len,
                                 const uint8_t *ad,
                                 size_t ad_len,
                                 const uint8_t *nonce) {
  int ret = 1;
  cty_sha256_opp_mem_ctx *ctx = (cty_sha256_opp_mem_ctx *)aead_key;

  // partial decrypt with no ad to msg and inner_tag
  uint8_t inner_tag[CTY_INNER_TAG_LEN] = {0};
  ret &= Aead_blake2b_opp_mem()->partial_open(
      (AeadKey *)ctx->sha256_opp_mem_ctx, msg, inner_tag, ct, ct_len, NULL, 0,
      nonce);

  // hash to tag and compare
  uint8_t expected_tag[CTY_OUTER_TAG_LEN] = {0};
  ret &= cty_hash(Hash_sha256(), expected_tag, ctx->key, nonce, ad, ad_len,
                  inner_tag);
  ret &= constant_time_compare(expected_tag, ct + ct_len - CTY_OUTER_TAG_LEN,
                               CTY_OUTER_TAG_LEN);
  return ret;
}

static const Aead cty_sha256_opp_mem = {"CTY[SHA256, Blake2b-OPP-MEM]",
                                        aead_cty_sha256_opp_mem_key_len,
                                        aead_cty_sha256_opp_mem_nonce_len,
                                        aead_cty_sha256_opp_mem_overhead,
                                        aead_cty_sha256_opp_mem_init,
                                        aead_cty_sha256_opp_mem_seal,
                                        aead_cty_sha256_opp_mem_open,
                                        NULL,
                                        NULL};

const Aead *Aead_cty_sha256_opp_mem() {
  return &cty_sha256_opp_mem;
}

/* ------------------------------------------------------------------------- */
/* Aead interface for CTY[Blake2b, Areion512-OPP-MEM]                        */

static const uint8_t aead_cty_areion512_opp_mem_key_len = CTY_KEY_LEN;
static const uint8_t aead_cty_areion512_opp_mem_nonce_len = CTY_NONCE_LEN;
static const uint8_t aead_cty_areion512_opp_mem_overhead = CTY_OUTER_TAG_LEN;

typedef struct {
  alignas(8) uint8_t areion512_opp_mem_ctx[32];
  alignas(8) uint8_t blake2b_ctx[248];
  // need a copy of the key since blake2b currently does not support resetting
  // state
  alignas(8) uint8_t key[32];
} cty_areion512_opp_mem_ctx;

int aead_cty_areion512_opp_mem_init(AeadKey *aead_key,
                                    const uint8_t *key,
                                    size_t key_len) {
  int ret = 1;
  cty_areion512_opp_mem_ctx *ctx = (cty_areion512_opp_mem_ctx *)aead_key;
  // init aead and hash with the same key
  assert(key_len == aead_cty_areion512_opp_mem_key_len);
  ret &= Aead_areion512_opp_mem()->init((AeadKey *)ctx->areion512_opp_mem_ctx,
                                        key, key_len);
  ret &= Hash_blake2b()->init((HashState *)ctx->blake2b_ctx, key, key_len,
                              CTY_OUTER_TAG_LEN);
  memcpy(ctx->key, key, aead_cty_areion512_opp_mem_key_len);
  return ret;
}

int aead_cty_areion512_opp_mem_seal(AeadKey *aead_key,
                                    uint8_t *ct,
                                    const uint8_t *msg,
                                    size_t msg_len,
                                    const uint8_t *ad,
                                    size_t ad_len,
                                    const uint8_t *nonce) {
  int ret = 1;
  cty_areion512_opp_mem_ctx *ctx = (cty_areion512_opp_mem_ctx *)aead_key;
  HashState *hash_ctx = (HashState *)ctx->blake2b_ctx;

  // encrypt with no ad to ct and inner_tag
  uint8_t inner_tag[CTY_INNER_TAG_LEN] = {0};
  ret &= Aead_areion512_opp_mem()->seal_scatter(
      (AeadKey *)ctx->areion512_opp_mem_ctx, ct, inner_tag, msg, msg_len, NULL,
      0, nonce);

  // hash to tag
  cty_hash(Hash_blake2b(), ct + msg_len, ctx->key, nonce, ad, ad_len,
           inner_tag);

  return ret;
}

int aead_cty_areion512_opp_mem_open(AeadKey *aead_key,
                                    uint8_t *msg,
                                    const uint8_t *ct,
                                    size_t ct_len,
                                    const uint8_t *ad,
                                    size_t ad_len,
                                    const uint8_t *nonce) {
  int ret = 1;
  cty_areion512_opp_mem_ctx *ctx = (cty_areion512_opp_mem_ctx *)aead_key;
  HashState *hash_ctx = (HashState *)ctx->blake2b_ctx;

  // partial decrypt with no ad to msg and inner_tag
  uint8_t inner_tag[CTY_INNER_TAG_LEN] = {0};
  ret &= Aead_areion512_opp_mem()->partial_open(
      (AeadKey *)ctx->areion512_opp_mem_ctx, msg, inner_tag, ct, ct_len, NULL,
      0, nonce);

  // hash to tag and compare
  uint8_t expected_tag[CTY_OUTER_TAG_LEN] = {0};
  ret &= cty_hash(Hash_blake2b(), expected_tag, ctx->key, nonce, ad, ad_len,
                  inner_tag);
  ret &= constant_time_compare(expected_tag, ct + ct_len - CTY_OUTER_TAG_LEN,
                               CTY_OUTER_TAG_LEN);
  return ret;
}

// FIXME: implement an Areion-based hash
static const Aead cty_areion512_opp_mem = {"CTY[Blake2b, Areion512-OPP-MEM]",
                                           aead_cty_areion512_opp_mem_key_len,
                                           aead_cty_areion512_opp_mem_nonce_len,
                                           aead_cty_areion512_opp_mem_overhead,
                                           aead_cty_areion512_opp_mem_init,
                                           aead_cty_areion512_opp_mem_seal,
                                           aead_cty_areion512_opp_mem_open,
                                           NULL,
                                           NULL};

const Aead *Aead_cty_areion512_opp_mem() {
  return &cty_areion512_opp_mem;
}