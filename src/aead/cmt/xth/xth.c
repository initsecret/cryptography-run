
#include <assert.h>

#include <cryptography-run/aead.h>
#include <cryptography-run/hash.h>
#include <string.h>
#include "../../../internal.h"

int xth_hash(const Hash *hash,
             uint8_t *digest,
             const uint8_t *key,
             size_t key_len,
             const uint8_t *nonce,
             size_t nonce_len,
             const uint8_t *ad,
             size_t ad_len,
             uint8_t *inner_tag,
             size_t inner_tag_len) {
  const size_t xth_output_len = 32;

  // FIXME: support taking a label

  HashState hash_ctx;

  int ret = 1;
  ret &= hash->init(&hash_ctx, key, key_len, xth_output_len);
  ret &= hash->update(&hash_ctx, nonce, nonce_len);
  if (ad_len < inner_tag_len) {
    // xor ad into inner_tag
    for (int i = 0; i < ad_len; i++) {
      inner_tag[i] ^= ad[i];
    }
    // xor 0xff into the next byte
    inner_tag[ad_len] ^= 0xff;
    // now hash the modified inner_tag
    ret &= hash->update(&hash_ctx, inner_tag, inner_tag_len);
  } else {
    // xor prefix of ad into inner_tag
    for (int i = 0; i < inner_tag_len; i++) {
      inner_tag[i] ^= ad[i];
    }
    // hash modified inner tag
    ret &= hash->update(&hash_ctx, inner_tag, inner_tag_len);
    // hash rest of ad
    ret &= hash->update(&hash_ctx, ad + inner_tag_len, ad_len - inner_tag_len);
    // hash a terminator byte
    uint8_t terminator[1] = {0xff};
    ret &= hash->update(&hash_ctx, terminator, 1);
  }
  ret &= hash->final(&hash_ctx, digest, xth_output_len);
  return ret;
}

#define XTH_BLAKE2B_OPP_MEM_INNER_TAG_LEN 32
#define XTH_BLAKE2B_OPP_MEM_TAG_LEN 32

static const uint8_t aead_xth_blake2b_opp_mem_key_len = 32;
static const uint8_t aead_xth_blake2b_opp_mem_nonce_len = 32;
static const uint8_t aead_xth_blake2b_opp_mem_overhead =
    XTH_BLAKE2B_OPP_MEM_TAG_LEN;

typedef struct {
  alignas(8) uint8_t blake2b_opp_mem_ctx[32];
  // need a copy of the key since blake2b currently does not support resetting
  // state
  alignas(8) uint8_t key[32];
} xth_blake2b_opp_mem_ctx;

int aead_xth_blake2b_opp_mem_init(AeadKey *aead_key,
                                  const uint8_t *key,
                                  size_t key_len) {
  int ret = 1;
  xth_blake2b_opp_mem_ctx *ctx = (xth_blake2b_opp_mem_ctx *)aead_key;
  // init aead and hash with the same key
  assert(key_len == aead_xth_blake2b_opp_mem_key_len);
  ret &= Aead_blake2b_opp_mem()->init((AeadKey *)ctx->blake2b_opp_mem_ctx, key,
                                      key_len);
  memcpy(ctx->key, key, aead_xth_blake2b_opp_mem_key_len);
  return ret;
}

int aead_xth_blake2b_opp_mem_seal(AeadKey *aead_key,
                                  uint8_t *ct,
                                  const uint8_t *msg,
                                  size_t msg_len,
                                  const uint8_t *ad,
                                  size_t ad_len,
                                  const uint8_t *nonce) {
  int ret = 1;
  xth_blake2b_opp_mem_ctx *ctx = (xth_blake2b_opp_mem_ctx *)aead_key;

  // encrypt with no ad to ct and inner_tag
  uint8_t inner_tag[XTH_BLAKE2B_OPP_MEM_INNER_TAG_LEN] = {0};
  ret &= Aead_blake2b_opp_mem()->seal_scatter(
      (AeadKey *)ctx->blake2b_opp_mem_ctx, ct, inner_tag, msg, msg_len, NULL, 0,
      nonce);

  // hash to tag
  ret &= xth_hash(Hash_blake2b(), ct + msg_len, ctx->key,
                  aead_xth_blake2b_opp_mem_key_len, nonce,
                  aead_xth_blake2b_opp_mem_nonce_len, ad, ad_len, inner_tag,
                  XTH_BLAKE2B_OPP_MEM_INNER_TAG_LEN);

  return ret;
}

int aead_xth_blake2b_opp_mem_open(AeadKey *aead_key,
                                  uint8_t *msg,
                                  const uint8_t *ct,
                                  size_t ct_len,
                                  const uint8_t *ad,
                                  size_t ad_len,
                                  const uint8_t *nonce) {
  int ret = 1;
  xth_blake2b_opp_mem_ctx *ctx = (xth_blake2b_opp_mem_ctx *)aead_key;

  // partial decrypt with no ad to msg and inner_tag
  uint8_t inner_tag[XTH_BLAKE2B_OPP_MEM_INNER_TAG_LEN] = {0};
  ret &= Aead_blake2b_opp_mem()->partial_open(
      (AeadKey *)ctx->blake2b_opp_mem_ctx, msg, inner_tag, ct, ct_len, NULL, 0,
      nonce);

  // hash to tag and compare
  uint8_t expected_tag[XTH_BLAKE2B_OPP_MEM_TAG_LEN] = {0};
  ret &= xth_hash(Hash_blake2b(), expected_tag, ctx->key,
                  aead_xth_blake2b_opp_mem_key_len, nonce,
                  aead_xth_blake2b_opp_mem_nonce_len, ad, ad_len, inner_tag,
                  XTH_BLAKE2B_OPP_MEM_INNER_TAG_LEN);
  ret &= constant_time_compare(expected_tag,
                               ct + ct_len - XTH_BLAKE2B_OPP_MEM_TAG_LEN,
                               XTH_BLAKE2B_OPP_MEM_TAG_LEN);
  return ret;
}

static const Aead xth_blake2b_opp_mem = {"XTH[Blake2b, Blake2b-OPP-MEM]",
                                         aead_xth_blake2b_opp_mem_key_len,
                                         aead_xth_blake2b_opp_mem_nonce_len,
                                         aead_xth_blake2b_opp_mem_overhead,
                                         aead_xth_blake2b_opp_mem_init,
                                         aead_xth_blake2b_opp_mem_seal,
                                         aead_xth_blake2b_opp_mem_open,
                                         NULL,
                                         NULL};

const Aead *Aead_xth_blake2b_opp_mem() {
  return &xth_blake2b_opp_mem;
}

int aead_xth_blake2b_sha256_opp_mem_seal(AeadKey *aead_key,
                                         uint8_t *ct,
                                         const uint8_t *msg,
                                         size_t msg_len,
                                         const uint8_t *ad,
                                         size_t ad_len,
                                         const uint8_t *nonce) {
  int ret = 1;
  xth_blake2b_opp_mem_ctx *ctx = (xth_blake2b_opp_mem_ctx *)aead_key;

  // encrypt with no ad to ct and inner_tag
  uint8_t inner_tag[XTH_BLAKE2B_OPP_MEM_INNER_TAG_LEN] = {0};
  ret &= Aead_blake2b_opp_mem()->seal_scatter(
      (AeadKey *)ctx->blake2b_opp_mem_ctx, ct, inner_tag, msg, msg_len, NULL, 0,
      nonce);

  // hash to tag
  ret &= xth_hash(Hash_sha256(), ct + msg_len, ctx->key,
                  aead_xth_blake2b_opp_mem_key_len, nonce,
                  aead_xth_blake2b_opp_mem_nonce_len, ad, ad_len, inner_tag,
                  XTH_BLAKE2B_OPP_MEM_INNER_TAG_LEN);

  return ret;
}

int aead_xth_blake2b_sha256_opp_mem_open(AeadKey *aead_key,
                                         uint8_t *msg,
                                         const uint8_t *ct,
                                         size_t ct_len,
                                         const uint8_t *ad,
                                         size_t ad_len,
                                         const uint8_t *nonce) {
  int ret = 1;
  xth_blake2b_opp_mem_ctx *ctx = (xth_blake2b_opp_mem_ctx *)aead_key;

  // partial decrypt with no ad to msg and inner_tag
  uint8_t inner_tag[XTH_BLAKE2B_OPP_MEM_INNER_TAG_LEN] = {0};
  ret &= Aead_blake2b_opp_mem()->partial_open(
      (AeadKey *)ctx->blake2b_opp_mem_ctx, msg, inner_tag, ct, ct_len, NULL, 0,
      nonce);

  // hash to tag and compare
  uint8_t expected_tag[XTH_BLAKE2B_OPP_MEM_TAG_LEN] = {0};
  ret &= xth_hash(Hash_sha256(), expected_tag, ctx->key,
                  aead_xth_blake2b_opp_mem_key_len, nonce,
                  aead_xth_blake2b_opp_mem_nonce_len, ad, ad_len, inner_tag,
                  XTH_BLAKE2B_OPP_MEM_INNER_TAG_LEN);
  ret &= constant_time_compare(expected_tag,
                               ct + ct_len - XTH_BLAKE2B_OPP_MEM_TAG_LEN,
                               XTH_BLAKE2B_OPP_MEM_TAG_LEN);
  return ret;
}

static const Aead xth_blake2b_sha256_opp_mem = {
    "XTH[SHA256, Blake2b-OPP-MEM]",
    aead_xth_blake2b_opp_mem_key_len,
    aead_xth_blake2b_opp_mem_nonce_len,
    aead_xth_blake2b_opp_mem_overhead,
    aead_xth_blake2b_opp_mem_init,
    aead_xth_blake2b_sha256_opp_mem_seal,
    aead_xth_blake2b_sha256_opp_mem_open,
    NULL,
    NULL};

const Aead *Aead_xth_blake2b_sha256_opp_mem() {
  return &xth_blake2b_sha256_opp_mem;
}