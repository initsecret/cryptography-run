#include <assert.h>

#include <cryptography-run/hash.h>

#include <KeccakHash.h>
#include <SimpleFIPS202.h>
#include <TurboSHAKE.h>
#include "../../internal.h"
#include "cryptography-run/aead.h"

/* ------------------------------------------------------------------------- */
/* Hash interface for SHA3-256                                               */

static const uint8_t hash_sha3_256_key_len = 32;
static const uint8_t hash_sha3_256_digest_len = 32;

typedef Keccak_HashInstance hash_sha3_ctx;

static int hash_sha3_256_hash(uint8_t *digest,
                              size_t digest_len,
                              const uint8_t *msg,
                              size_t msg_len) {
  assert(digest_len == hash_sha3_256_digest_len);
  // NOTE: returns zero on success
  return (SHA3_256(digest, msg, msg_len) == 0);
}

static int hash_sha3_256_init(HashState *hash_ctx,
                              const uint8_t *key,
                              size_t key_len,
                              size_t digest_length) {
  hash_sha3_ctx *ctx = (hash_sha3_ctx *)hash_ctx;
  assert(digest_length == hash_sha3_256_digest_len);

  HashReturn result = Keccak_HashInitialize_SHA3_256(ctx);
  if (result != KECCAK_SUCCESS) {
    return 0;
  }
  if (key_len > 0) {
    BitLength key_bitlen = key_len * 8;
    result = Keccak_HashUpdate(ctx, key, key_bitlen);
    if (result != KECCAK_SUCCESS) {
      return 0;
    }
  }
  return 1;
}

static int hash_sha3_256_update(HashState *hash_ctx,
                                const uint8_t *in,
                                size_t in_len) {
  hash_sha3_ctx *ctx = (hash_sha3_ctx *)hash_ctx;
  BitLength in_bitlen = in_len * 8;
  HashReturn result = Keccak_HashUpdate(ctx, in, in_bitlen);
  return (result == KECCAK_SUCCESS);
}

static int hash_sha3_256_final(HashState *hash_ctx,
                               uint8_t *digest,
                               size_t digest_len) {
  assert(digest_len == hash_sha3_256_digest_len);
  hash_sha3_ctx *ctx = (hash_sha3_ctx *)hash_ctx;
  HashReturn result = Keccak_HashFinal(ctx, digest);
  return (result == KECCAK_SUCCESS);
}

static int hash_sha3_256_keyed_hash(const uint8_t *key,
                                    size_t key_len,
                                    uint8_t *digest,
                                    size_t digest_len,
                                    const uint8_t *msg,
                                    size_t msg_len) {
  assert(digest_len == hash_sha3_256_digest_len);
  int ret = 1;
  HashState ctx;
  ret &= hash_sha3_256_init(&ctx, key, key_len, digest_len);
  ret &= hash_sha3_256_update(&ctx, msg, msg_len);
  ret &= hash_sha3_256_final(&ctx, digest, digest_len);
  return ret;
}

static const Hash hash_sha3_256 = {
    "sha3_256",           hash_sha3_256_key_len,    hash_sha3_256_digest_len,
    hash_sha3_256_hash,   hash_sha3_256_keyed_hash, hash_sha3_256_init,
    hash_sha3_256_update, hash_sha3_256_final};

const Hash *Hash_sha3_256() {
  return &hash_sha3_256;
}

/* ------------------------------------------------------------------------- */
/* Aead interface for TurboSHAKE128                                          */

static const uint8_t aead_turboshake128_key_len = 32;
static const uint8_t aead_turboshake128_pubnonce_len = 16;
static const uint8_t aead_turboshake128_secnonce_len = 0;
static const uint8_t aead_turboshake128_overhead = 32;

// 224 bytes
typedef TurboSHAKE_Instance turboshake128_ctx;

int aead_turboshake128_init(AeadKey *aead_key,
                            const uint8_t *key,
                            size_t key_len) {
  turboshake128_ctx *ctx = (turboshake128_ctx *)aead_key;
  int result = TurboSHAKE128_Initialize(ctx);
  return (result == KECCAK_SUCCESS);
}

int aead_turboshake128_seal(AeadKey *aead_key,
                            uint8_t *ct,
                            const uint8_t *msg,
                            size_t msg_len,
                            const uint8_t *ad,
                            size_t ad_len,
                            const uint8_t *pubnonce,
                            const uint8_t *secnonce) {
  int res = 0;
  turboshake128_ctx *ctx = (turboshake128_ctx *)aead_key;

  // need to reset sponge
  res |= TurboSHAKE128_Initialize(ctx);
  res |= TurboSHAKE_Absorb(ctx, pubnonce, aead_turboshake128_pubnonce_len);
  res |= TurboSHAKE_Absorb(ctx, ad, ad_len);
  res |= TurboSHAKE_Absorb(ctx, msg, msg_len);

  // hash to tag
  uint8_t *tag = ct + msg_len;
  res |= TurboSHAKE_Squeeze(ctx, tag, 32);
  return (res == 0);
}

int aead_turboshake128_open(AeadKey *aead_key,
                            uint8_t *msg,
                            uint8_t *secnonce,
                            const uint8_t *ct,
                            size_t ct_len,
                            const uint8_t *ad,
                            size_t ad_len,
                            const uint8_t *pubnonce) {
  int res = 0;
  turboshake128_ctx *ctx = (turboshake128_ctx *)aead_key;

  // need to reset sponge
  res |= TurboSHAKE128_Initialize(ctx);
  res |= TurboSHAKE_Absorb(ctx, pubnonce, aead_turboshake128_pubnonce_len);
  res |= TurboSHAKE_Absorb(ctx, ad, ad_len);
  res |= TurboSHAKE_Absorb(ctx, ct, ct_len - 32);

  // hash to tag and compare
  uint8_t expected_tag[32] = {0};
  res |= TurboSHAKE_Squeeze(ctx, expected_tag, 32);
  const uint8_t *tag = ct + ct_len - 32;
  int ret = constant_time_compare(expected_tag, tag, 32);
  return (res == 0) && ret;
}

static const Aead turboshake128 = {"Aead-TurboSHAKE128",
                                   aead_turboshake128_key_len,
                                   aead_turboshake128_pubnonce_len,
                                   aead_turboshake128_secnonce_len,
                                   aead_turboshake128_overhead,
                                   aead_turboshake128_init,
                                   aead_turboshake128_seal,
                                   aead_turboshake128_open,
                                   NULL,
                                   NULL};

const Aead *Aead_turboshake128() {
  return &turboshake128;
}

/* ------------------------------------------------------------------------- */
/* Aead interface for SHAKE128                                          */

// 224 bytes
typedef Keccak_HashInstance shake128_ctx;

int aead_shake128_init(AeadKey *aead_key, const uint8_t *key, size_t key_len) {
  shake128_ctx *ctx = (shake128_ctx *)aead_key;
  int result = Keccak_HashInitialize_SHAKE128(ctx);
  return (result == KECCAK_SUCCESS);
}

int aead_shake128_seal(AeadKey *aead_key,
                       uint8_t *ct,
                       const uint8_t *msg,
                       size_t msg_len,
                       const uint8_t *ad,
                       size_t ad_len,
                       const uint8_t *pubnonce,
                       const uint8_t *secnonce) {
  int res = 0;
  shake128_ctx *ctx = (shake128_ctx *)aead_key;

  // need to reset sponge
  res |= Keccak_HashInitialize_SHAKE128(ctx);
  res |= Keccak_HashUpdate(ctx, msg, msg_len * 8);
  res |= Keccak_HashUpdate(ctx, ad, ad_len * 8);

  // hash to tag
  uint8_t *tag = ct + msg_len;
  res |= Keccak_HashFinal(ctx, tag);
  return (res == 0);
}

int aead_shake128_open(AeadKey *aead_key,
                       uint8_t *msg,
                       uint8_t *secnonce,
                       const uint8_t *ct,
                       size_t ct_len,
                       const uint8_t *ad,
                       size_t ad_len,
                       const uint8_t *pubnonce) {
  int res = 0;
  shake128_ctx *ctx = (shake128_ctx *)aead_key;

  res |= Keccak_HashInitialize_SHAKE128(ctx);
  res |= Keccak_HashUpdate(ctx, ct, (ct_len - 32) * 8);
  res |= Keccak_HashUpdate(ctx, ad, ad_len * 8);

  // hash to tag and compare
  uint8_t expected_tag[32] = {0};
  res |= Keccak_HashFinal(ctx, expected_tag);
  const uint8_t *tag = ct + ct_len - 32;
  int ret = constant_time_compare(expected_tag, tag, 32);
  return (res == 0) && ret;
}

static const Aead shake128 = {"Aead-SHAKE128",
                              aead_turboshake128_key_len,
                              aead_turboshake128_pubnonce_len,
                              aead_turboshake128_secnonce_len,
                              aead_turboshake128_overhead,
                              aead_shake128_init,
                              aead_shake128_seal,
                              aead_shake128_open,
                              NULL,
                              NULL};

const Aead *Aead_shake128() {
  return &shake128;
}