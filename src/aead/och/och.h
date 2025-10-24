/*
    OCH over a generic TBC, AXU hash, and CR hash.

    :copyright: (c) 2025 by OCH authors.
    :license: Creative Commons CC0 1.0
*/

#ifndef CR_OCH_H
#define CR_OCH_H

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>

#include <cryptography-run/aead.h>
#include <cryptography-run/axuhash.h>
#include <cryptography-run/hash.h>

#include "trans.h"

#if defined(__cplusplus)
extern "C" {
#endif

static const uint8_t och_key_len = 32;

static const uint8_t och_checksum_len = 16;
typedef u128_t OchChecksum;

static const uint8_t och256_perm_width = 32;

static const uint8_t och_tag_len = 32;

static const uint8_t och_s_pubnonce_len = 0;
static const uint8_t och_s_secnonce_len = 32;
static const uint8_t och_s_overhead = och_s_secnonce_len + och_tag_len;

static const uint8_t och_p_pubnonce_len = 32;
static const uint8_t och_p_secnonce_len = 0;
static const uint8_t och_p_overhead = och_p_secnonce_len + och_tag_len;

// Can support any 256-bit hash function
static const size_t och_digest_len = 32;

static const uint8_t label_och_kg_tbc = 0xf0;
static const uint8_t label_och_kg_axu = 0xf1;
static const uint8_t label_och_tiny = 0xf2;
static const uint8_t label_och_core_no_partial = 0xf3;
static const uint8_t label_och_core_with_partial = 0xf4;

/**
 * Compute OCH-Tiny tag
 */
static int OCH_compute_tag_tiny(const Hash *crhash,
                                const HashState *crhash_ctx,
                                const AxuHash *axuhash,
                                const AxuHashKey *axuhash_key,
                                uint8_t *tag,
                                const uint8_t *P,
                                size_t P_len,
                                const uint8_t *ad,
                                size_t ad_len,
                                const uint8_t *public_nonce,
                                size_t public_nonce_len,
                                const uint8_t *secret_nonce,
                                size_t secret_nonce_len) {
  int ret = 1;

  assert(axuhash->digest_len <= 32);
  uint8_t axu_out[32] = {0};

  assert(secret_nonce_len == 0);
  assert(P_len <= 31);

  // axu_in is P || label < 32 + 1 bytes <= 32 bytes
  // we pad this to 32 bytes
  uint8_t axu_in[32] = {0};
  memcpy(axu_in, P, P_len);
  axu_in[P_len] = label_och_tiny;

  ret &= axuhash->update_and_final(axuhash_key, axu_out, axuhash->digest_len,
                                   axu_in, 32);
  ret &= Hash_xth_tag(crhash, crhash_ctx, tag, ad, ad_len, public_nonce,
                      public_nonce_len, axu_out, axuhash->digest_len);
  return ret;
}

/**
 * Compute OCH tag with no partial block
 */
static int OCH_compute_tag_no_partial(const Hash *crhash,
                                      HashState *crhash_ctx,
                                      const AxuHash *axuhash,
                                      const AxuHashKey *axuhash_key,
                                      uint8_t *tag,
                                      size_t msg_len,
                                      const uint8_t *ad,
                                      size_t ad_len,
                                      const uint8_t *public_nonce,
                                      size_t public_nonce_len,
                                      const uint8_t *secret_nonce,
                                      size_t secret_nonce_len,
                                      OchChecksum checksum) {
  int ret = 1;
  bool is_partial = false;
  uint64_t num_blocks = (msg_len >> 5);  // msg_len // 32
  uint64_t mlen = (num_blocks << 1) | is_partial;

  assert(axuhash->digest_len <= 32);
  uint8_t axu_out[32] = {0};
  if (secret_nonce_len > 0) {
    assert(secret_nonce_len <= och_s_secnonce_len);
    // axu_in is secret nonce || checksum || mlen = 256 + 128 + 64 bits
    // we pad this to 512 bits
    size_t unpadded_axu_in_len = secret_nonce_len + 16 + 8;
    assert(unpadded_axu_in_len < 64);
    uint8_t axu_in[64] = {0};
    memcpy(axu_in, secret_nonce, secret_nonce_len);
    store128(axu_in + secret_nonce_len, checksum);
    memcpy(axu_in + secret_nonce_len + och_checksum_len, (uint8_t *)&mlen, 8);
    axu_in[unpadded_axu_in_len] = label_och_core_no_partial;

    ret &= axuhash->update_and_final(axuhash_key, axu_out, axuhash->digest_len,
                                     axu_in, 64);
    ret &= Hash_xth_tag(crhash, crhash_ctx, tag, ad, ad_len, public_nonce,
                        public_nonce_len, axu_out, axuhash->digest_len);
    return ret;
  } else {
    // axu_in is checksum || mlen = 128 + 64 bits
    // we pad this to 256 bits
    size_t unpadded_axu_in_len = 16 + 8;
    assert(unpadded_axu_in_len < 32);
    uint8_t axu_in[32] = {0};
    store128(axu_in, checksum);
    memcpy(axu_in + och_checksum_len, (uint8_t *)&mlen, 8);
    axu_in[unpadded_axu_in_len] = label_och_core_no_partial;

    ret &= axuhash->update_and_final(axuhash_key, axu_out, axuhash->digest_len,
                                     axu_in, 32);
    ret &= Hash_xth_tag(crhash, crhash_ctx, tag, ad, ad_len, public_nonce,
                        public_nonce_len, axu_out, axuhash->digest_len);
    return ret;
  }
}

/**
 * Compute OCH tag with with partial block
 */
static int OCH_compute_tag_with_partial(const Hash *crhash,
                                        HashState *crhash_ctx,
                                        const AxuHash *axuhash,
                                        const AxuHashKey *axuhash_key,
                                        uint8_t *tag,
                                        size_t msg_len,
                                        const uint8_t *ad,
                                        size_t ad_len,
                                        const uint8_t *public_nonce,
                                        size_t public_nonce_len,
                                        const uint8_t *secret_nonce,
                                        size_t secret_nonce_len,
                                        const uint8_t *extended_checksum,
                                        size_t extended_checksum_len) {
  int ret = 1;
  bool is_partial = true;
  uint64_t num_blocks = (msg_len >> 5);  // msg_len // 32
  uint64_t mlen = (num_blocks << 1) | is_partial;

  assert(axuhash->digest_len <= 32);
  uint8_t axu_out[32] = {0};
  if (secret_nonce_len > 0) {
    assert(secret_nonce_len <= och_s_secnonce_len);
    // axu_in is secret_nonce || extended_checksum || mlen < 256 + 256 + 64 bits
    // we pad this to 640 bits
    size_t unpadded_axu_in_len = secret_nonce_len + extended_checksum_len + 8;
    assert(unpadded_axu_in_len < 80);
    uint8_t axu_in[80] = {0};
    memcpy(axu_in, secret_nonce, secret_nonce_len);
    memcpy(axu_in + secret_nonce_len, extended_checksum, extended_checksum_len);
    memcpy(axu_in + secret_nonce_len + extended_checksum_len, (uint8_t *)&mlen,
           8);
    axu_in[unpadded_axu_in_len] = label_och_core_with_partial;

    ret &= axuhash->update_and_final(axuhash_key, axu_out, axuhash->digest_len,
                                     axu_in, 80);
    ret &= Hash_xth_tag(crhash, crhash_ctx, tag, ad, ad_len, public_nonce,
                        public_nonce_len, axu_out, axuhash->digest_len);
    return ret;
  } else {
    // axu_in is extended_checksum || mlen < 256 + 64 bits
    // we pad this to 384 bits
    size_t unpadded_axu_in_len = extended_checksum_len + 8;
    assert(unpadded_axu_in_len < 48);
    uint8_t axu_in[48] = {0};
    memcpy(axu_in, extended_checksum, extended_checksum_len);
    memcpy(axu_in + extended_checksum_len, (uint8_t *)&mlen, 8);
    axu_in[unpadded_axu_in_len] = label_och_core_with_partial;

    ret &= axuhash->update_and_final(axuhash_key, axu_out, axuhash->digest_len,
                                     axu_in, 48);
    ret &= Hash_xth_tag(crhash, crhash_ctx, tag, ad, ad_len, public_nonce,
                        public_nonce_len, axu_out, axuhash->digest_len);
    return ret;
  }
}

#ifdef __cplusplus
}
#endif

#endif  // CR_OCH_H
