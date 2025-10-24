/*
    OCH with 256-bit OCT over generic AXU hash and CR hash.

    :copyright: (c) 2025 by OCH authors.
    :license: Creative Commons CC0 1.0
*/

#ifndef CR_OCH256_H
#define CR_OCH256_H

#include <cryptography-run/aead.h>
#include <cryptography-run/axuhash.h>
#include <cryptography-run/base.h>
#include <cryptography-run/hash.h>

#include "trans.h"

#include "och.h"
#include "oct256.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct {
  const EM256 *oct;
  const Hash *crhash;
  const AxuHash *axuhash;
  uint8_t pubnonce_len;
  uint8_t secnonce_len;
  alignas(32) HashState crhash_ctx;
  alignas(32) AxuHashKey axuhash_key;
  alignas(32) Oct256State oct_ctx;
} OCH256_ctx;

static int OCH256_init(const EM256 *oct,
                       const Hash *crhash,
                       const AxuHash *axuhash,
                       const uint8_t pubnonce_len,
                       const uint8_t secnonce_len,
                       AeadKey *aead_key,
                       const uint8_t *key,
                       size_t key_len) {
  int ret = 1;
  OCH256_ctx *ctx = (OCH256_ctx *)aead_key;

  // configure OCT
  ctx->oct = oct;
  ctx->crhash = crhash;
  ctx->axuhash = axuhash;
  ctx->pubnonce_len = pubnonce_len;
  ctx->secnonce_len = secnonce_len;

  // XXX: consider hashing the configuration to derive subkeys

  assert(key_len == 32);
  // precompute keyed hash state
  ret &= crhash->init(&ctx->crhash_ctx, key, key_len, och_digest_len);
  // derive subkeys using hash
  // do two 32-byte calls so we can use any 256-bit hash function.
  uint8_t raw_tbc_key[32] = {0};
  ret &=
      crhash->keyed_hash(key, key_len, raw_tbc_key, 32, &label_och_kg_tbc, 1);
  ret &= Oct256_setup(oct, &ctx->oct_ctx, raw_tbc_key, 32);
  uint8_t raw_axu_key[32] = {0};
  ret &=
      crhash->keyed_hash(key, key_len, raw_axu_key, 32, &label_och_kg_axu, 1);
  assert(axuhash->key_len <= 32);
  assert(axuhash->digest_len <= 32);
  ret &= axuhash->init(&ctx->axuhash_key, raw_axu_key, axuhash->key_len,
                       axuhash->digest_len);

  return ret;
}

#ifdef __cplusplus
}
#endif

#endif  // CR_OCH256_H
