#include <assert.h>

#include <cryptography-run/hash.h>

#include <asconaeadxof128.h>
#include "cryptography-run/aead.h"

/* ------------------------------------------------------------------------- */
/* Hash interface for Ascon-Hash256                                          */

static const uint8_t hash_ascon256_key_len = 32;
static const uint8_t hash_ascon256_digest_len = 32;

typedef ascon_state_t ascon_ctx;

static int hash_ascon256_hash(uint8_t *digest,
                              size_t digest_len,
                              const uint8_t *msg,
                              size_t msg_len) {
  assert(digest_len == hash_ascon256_digest_len);
  // NOTE: returns zero on success
  return (ascon_xof(digest, digest_len, msg, msg_len) == 0);
}

static int hash_ascon256_init(HashState *hash_ctx,
                              const uint8_t *key,
                              size_t key_len,
                              size_t digest_length) {
  ascon_ctx *ctx = (ascon_ctx *)hash_ctx;
  assert(digest_length == hash_ascon256_digest_len);

  ascon_inithash(ctx);
  ascon_absorb(ctx, key, key_len);
  return 1;
}

static int hash_ascon256_update(HashState *hash_ctx,
                                const uint8_t *in,
                                size_t in_len) {
  ascon_ctx *ctx = (ascon_ctx *)hash_ctx;
  ascon_absorb(ctx, in, in_len);
  return 1;
}

static int hash_ascon256_final(HashState *hash_ctx,
                               uint8_t *digest,
                               size_t digest_len) {
  assert(digest_len == hash_ascon256_digest_len);
  ascon_ctx *ctx = (ascon_ctx *)hash_ctx;
  ascon_squeeze(ctx, digest, digest_len);
  return 1;
}

static int hash_ascon256_keyed_hash(const uint8_t *key,
                                    size_t key_len,
                                    uint8_t *digest,
                                    size_t digest_len,
                                    const uint8_t *msg,
                                    size_t msg_len) {
  assert(digest_len == hash_ascon256_digest_len);
  int ret = 1;
  HashState ctx;
  ret &= hash_ascon256_init(&ctx, key, key_len, digest_len);
  ret &= hash_ascon256_update(&ctx, msg, msg_len);
  ret &= hash_ascon256_final(&ctx, digest, digest_len);
  return ret;
}

static const Hash hash_ascon256 = {
    "Ascon-Hash256",      hash_ascon256_key_len,    hash_ascon256_digest_len,
    hash_ascon256_hash,   hash_ascon256_keyed_hash, hash_ascon256_init,
    hash_ascon256_update, hash_ascon256_final};

const Hash *Hash_ascon256() {
  return &hash_ascon256;
}

/* ------------------------------------------------------------------------- */
/* Aead interface for Ascon-AEAD128                                          */

static const uint8_t aead_ascon128_key_len = 16;
static const uint8_t aead_ascon128_pubnonce_len = 16;
static const uint8_t aead_ascon128_secnonce_len = 0;
static const uint8_t aead_ascon128_overhead = 16;

typedef struct {
  ascon_key_t ascon_key;
} ascon128_ctx;

int aead_ascon128_init(AeadKey *aead_key, const uint8_t *key, size_t key_len) {
  ascon128_ctx *ctx = (ascon128_ctx *)aead_key;
  assert(key_len == aead_ascon128_key_len);
  ascon_loadkey(&ctx->ascon_key, key);
  return 1;
}

int aead_ascon128_seal_scatter(AeadKey *aead_key,
                               uint8_t *ctcore,
                               uint8_t *tag,
                               const uint8_t *msg,
                               size_t msg_len,
                               const uint8_t *ad,
                               size_t ad_len,
                               const uint8_t *pubnonce,
                               const uint8_t *subnonce) {
  ascon128_ctx *ctx = (ascon128_ctx *)aead_key;

  ascon_state_t state;
  ascon_initaead(&state, &ctx->ascon_key, pubnonce);
  ascon_adata(&state, ad, ad_len);
  ascon_encrypt(&state, ctcore, msg, msg_len);
  ascon_final(&state, &ctx->ascon_key);
  ascon_gettag(&state, tag);
  return 1;
}

int aead_ascon128_partial_open(AeadKey *aead_key,
                               uint8_t *msg,
                               uint8_t *secnonce,
                               uint8_t *tag,
                               const uint8_t *ctcore,
                               size_t ctcore_len,
                               const uint8_t *ad,
                               size_t ad_len,
                               const uint8_t *pubnonce) {
  ascon128_ctx *ctx = (ascon128_ctx *)aead_key;

  ascon_state_t state;
  ascon_initaead(&state, &ctx->ascon_key, pubnonce);
  ascon_adata(&state, ad, ad_len);
  ascon_decrypt(&state, msg, ctcore, ctcore_len);
  ascon_final(&state, &ctx->ascon_key);
  ascon_gettag(&state, tag);
  return 1;
}

int aead_ascon128_seal(AeadKey *aead_key,
                       uint8_t *ct,
                       const uint8_t *msg,
                       size_t msg_len,
                       const uint8_t *ad,
                       size_t ad_len,
                       const uint8_t *pubnonce,
                       const uint8_t *secnonce) {
  uint8_t *ctcore = ct;
  uint8_t *tag = ct + msg_len;
  return aead_ascon128_seal_scatter(aead_key, ctcore, tag, msg, msg_len, ad,
                                    ad_len, pubnonce, secnonce);
}

int aead_ascon128_open(AeadKey *aead_key,
                       uint8_t *msg,
                       uint8_t *secnonce,
                       const uint8_t *ct,
                       size_t ct_len,
                       const uint8_t *ad,
                       size_t ad_len,
                       const uint8_t *pubnonce) {
  const uint8_t *ctcore = ct;
  size_t ctcore_len = ct_len - aead_ascon128_overhead;
  const uint8_t *tag = ct + ctcore_len;

  ascon128_ctx *ctx = (ascon128_ctx *)aead_key;

  ascon_state_t state;
  ascon_initaead(&state, &ctx->ascon_key, pubnonce);
  ascon_adata(&state, ad, ad_len);
  ascon_decrypt(&state, msg, ctcore, ctcore_len);
  ascon_final(&state, &ctx->ascon_key);
  // NOTE: returns zero on success
  return (ascon_verify(&state, tag) == 0);
}

static const Aead ascon128 = {"Ascon-AEAD128",
                              aead_ascon128_key_len,
                              aead_ascon128_pubnonce_len,
                              aead_ascon128_secnonce_len,
                              aead_ascon128_overhead,
                              aead_ascon128_init,
                              aead_ascon128_seal,
                              aead_ascon128_open,
                              aead_ascon128_seal_scatter,
                              aead_ascon128_partial_open};

const Aead *Aead_ascon128() {
  return &ascon128;
}