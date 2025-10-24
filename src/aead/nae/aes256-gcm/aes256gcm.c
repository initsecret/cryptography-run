#include <assert.h>

#include <cryptography-run/aead.h>

#include "aes256gcm_skylake.h"

static const uint8_t aead_aes256gcm_key_len =
    HABERDASHERY_AES_256_GCM_SKYLAKE_KEY_LEN;
static const uint8_t aead_aes256gcm_pubnonce_len =
    HABERDASHERY_AES_256_GCM_SKYLAKE_NONCE_LEN;
static const uint8_t aead_aes256gcm_secnonce_len = 0;
static const uint8_t aead_aes256gcm_overhead =
    HABERDASHERY_AES_256_GCM_SKYLAKE_TAG_LEN;

static int aead_aes256gcm_init(AeadKey *aead_key,
                               const uint8_t *key,
                               size_t key_len) {
  haberdashery_aes256gcm_skylake_t *ctx =
      (haberdashery_aes256gcm_skylake_t *)aead_key;
  haberdashery_aes256gcm_skylake_init(ctx, key, key_len);
  return 1;
}

static int aead_aes256gcm_seal(AeadKey *aead_key,
                               uint8_t *ct,
                               const uint8_t *msg,
                               size_t msg_len,
                               const uint8_t *ad,
                               size_t ad_len,
                               const uint8_t *pubnonce,
                               const uint8_t *secnonce) {
  haberdashery_aes256gcm_skylake_t *ctx =
      (haberdashery_aes256gcm_skylake_t *)aead_key;
  uint8_t *ctcore = ct;
  size_t ctcore_len = msg_len;
  uint8_t *tag = ct + msg_len;
  size_t tag_len = aead_aes256gcm_overhead;
  return haberdashery_aes256gcm_skylake_encrypt(
      ctx, pubnonce, aead_aes256gcm_pubnonce_len, ad, ad_len, msg, msg_len,
      ctcore, ctcore_len, tag, tag_len);
}

static int aead_aes256gcm_open(AeadKey *aead_key,
                               uint8_t *msg,
                               uint8_t *secnonce,
                               const uint8_t *ct,
                               size_t ct_len,
                               const uint8_t *ad,
                               size_t ad_len,
                               const uint8_t *pubnonce) {
  haberdashery_aes256gcm_skylake_t *ctx =
      (haberdashery_aes256gcm_skylake_t *)aead_key;
  size_t tag_len = aead_aes256gcm_overhead;
  size_t msg_len = ct_len - tag_len;
  const uint8_t *ctcore = ct;
  size_t ctcore_len = msg_len;
  const uint8_t *tag = ct + msg_len;
  return haberdashery_aes256gcm_skylake_decrypt(
      ctx, pubnonce, aead_aes256gcm_pubnonce_len, ad, ad_len, ctcore,
      ctcore_len, tag, tag_len, msg, msg_len);
}

static int aead_aes256gcm_seal_scatter(AeadKey *aead_key,
                                       uint8_t *ctcore,
                                       uint8_t *tag,
                                       const uint8_t *msg,
                                       size_t msg_len,
                                       const uint8_t *ad,
                                       size_t ad_len,
                                       const uint8_t *nonce,
                                       const uint8_t *secnonce) {
  haberdashery_aes256gcm_skylake_t *ctx =
      (haberdashery_aes256gcm_skylake_t *)aead_key;
  size_t ctcore_len = msg_len;
  size_t tag_len = aead_aes256gcm_overhead;
  return haberdashery_aes256gcm_skylake_encrypt(
      ctx, nonce, aead_aes256gcm_pubnonce_len, ad, ad_len, msg, msg_len, ctcore,
      ctcore_len, tag, tag_len);
}

static int aead_aes256gcm_partial_open(AeadKey *aead_key,
                                       uint8_t *msg,
                                       uint8_t *secnonce,
                                       uint8_t *tag,
                                       const uint8_t *ctcore,
                                       size_t ctcore_len,
                                       const uint8_t *ad,
                                       size_t ad_len,
                                       const uint8_t *pubnonce) {
  haberdashery_aes256gcm_skylake_t *ctx =
      (haberdashery_aes256gcm_skylake_t *)aead_key;
  size_t tag_len = aead_aes256gcm_overhead;
  // decryption will fail since the tag is wrong, but it should produce the
  // correct message
  int dec_res = haberdashery_aes256gcm_skylake_decrypt(
      ctx, pubnonce, aead_aes256gcm_pubnonce_len, ad, ad_len, ctcore,
      ctcore_len, tag, tag_len, msg, ctcore_len);
  assert(dec_res == 0);
  int ret = 1;
  // now encrypt the message to generate the correct tag
  ret &= haberdashery_aes256gcm_skylake_encrypt(
      ctx, pubnonce, aead_aes256gcm_pubnonce_len, ad, ad_len, msg, ctcore_len,
      msg, ctcore_len, tag, tag_len);
  // now decrypt again with the right tag
  ret &= haberdashery_aes256gcm_skylake_decrypt(
      ctx, pubnonce, aead_aes256gcm_pubnonce_len, ad, ad_len, ctcore,
      ctcore_len, tag, tag_len, msg, ctcore_len);
  return ret;
}

static const Aead aes256gcm = {
    "Haberdashery-AES256-GCM",   aead_aes256gcm_key_len,
    aead_aes256gcm_pubnonce_len, aead_aes256gcm_secnonce_len,
    aead_aes256gcm_overhead,     aead_aes256gcm_init,
    aead_aes256gcm_seal,         aead_aes256gcm_open,
    aead_aes256gcm_seal_scatter, aead_aes256gcm_partial_open};

const Aead *Aead_aes256_gcm() {
  return &aes256gcm;
}
