/*
    CTY and XtH transforms

    :copyright: (c) 2025 by OCH authors.
    :license: Creative Commons CC0 1.0
*/

#ifndef CR_TRANS_H
#define CR_TRANS_H

#include <assert.h>
#include <stdint.h>

#include <cryptography-run/hash.h>

#if defined(__cplusplus)
extern "C" {
#endif

/** API for generating the outer tag, matches CTY and XtH */
typedef int (*trans_tag)(const Hash *crhash,
                         const HashState *crhash_ctx,
                         uint8_t *tag,
                         const uint8_t *ad,
                         size_t ad_len,
                         const uint8_t *public_nonce,
                         size_t public_nonce_len,
                         const uint8_t *inner_tag,
                         size_t inner_tag_len);

/**
 * Hash: Compute tag using CTY
 */
static int Hash_cty_tag(const Hash *crhash,
                        const HashState *crhash_ctx,
                        uint8_t *tag,
                        const uint8_t *ad,
                        size_t ad_len,
                        const uint8_t *public_nonce,
                        size_t public_nonce_len,
                        const uint8_t *inner_tag,
                        size_t inner_tag_len) {
  int ret = 1;
  HashState ctx;
  ctx = *crhash_ctx;

  ret &= crhash->update(&ctx, inner_tag, inner_tag_len);
  ret &= crhash->update(&ctx, ad, ad_len);
  if (public_nonce_len > 0) {
    ret &= crhash->update(&ctx, public_nonce, public_nonce_len);
  }
  ret &= crhash->final(&ctx, tag, 32);
  return ret;
}

/**
 * Hash: Compute tag using XtH
 */
static int Hash_xth_tag(const Hash *crhash,
                        const HashState *crhash_ctx,
                        uint8_t *tag,
                        const uint8_t *ad,
                        size_t ad_len,
                        const uint8_t *public_nonce,
                        size_t public_nonce_len,
                        const uint8_t *inner_tag,
                        size_t inner_tag_len) {
  int ret = 1;
  HashState ctx = *crhash_ctx;
  assert(inner_tag_len <= 32);
  if (ad_len < inner_tag_len) {
    uint8_t sponge_in[32] = {0};
    // ixor(itag, ad) = itag ^ (ad || 0xff)
    // bytelen(ixor(itag, ad)) = bytelen(itag)
    for (int idx = 0; idx < ad_len; idx++) {
      sponge_in[idx] = inner_tag[idx] ^ ad[idx];
    }
    sponge_in[ad_len] ^= 0xff;
    ret &= crhash->update(&ctx, sponge_in, inner_tag_len);
  } else {
    // ixor(itag, ad) = itag ^ (ad || 0xff)
    //               = (itag ^ ad[:32]) || ad[32:] || 0xff
    // bytelen(ixor(itag, ad)) = bytelen(ad) + 1
    uint8_t sponge_in[32] = {0};
    int ad_idx = 0;
    for (; ad_idx < inner_tag_len; ad_idx++) {
      sponge_in[ad_idx] = inner_tag[ad_idx] ^ ad[ad_idx];
    }
    ret &= crhash->update(&ctx, sponge_in, inner_tag_len);
    if (ad_len > inner_tag_len) {
      ret &= crhash->update(&ctx, ad + inner_tag_len, ad_len - inner_tag_len);
    }
  }

  if (public_nonce_len > 0) {
    ret &= crhash->update(&ctx, public_nonce, public_nonce_len);
  }
  ret &= crhash->final(&ctx, tag, 32);
  return ret;
}

#ifdef __cplusplus
}
#endif

#endif  // CR_TRANS_H