#include <cryptography-run/aead.h>

#include <aegis.h>

/* ------------------------------------------------------------------------- */
/* Aead interface for Aegis256                                               */

static const uint8_t aegis256_tag_len = 32;

static const uint8_t aead_aegis256_key_len = 32;
static const uint8_t aead_aegis256_pubnonce_len = 32;
static const uint8_t aead_aegis256_secnonce_len = 0;
static const uint8_t aead_aegis256_overhead = aegis256_tag_len;

// Aegis256 does not support key-only initialization, so we just store the key
// and do initialization in encrypt and decrypt which have access to the nonce.
typedef struct {
  alignas(32) uint8_t key[32];
} aegis256_ctx;

int aead_aegis256_init(AeadKey *aead_key, const uint8_t *key, size_t key_len) {
  aegis256_ctx *ctx = (aegis256_ctx *)aead_key;
  memcpy(ctx->key, key, aead_aegis256_key_len);
  return 1;
}

int aead_aegis256_seal(AeadKey *aead_key,
                       uint8_t *ct,
                       const uint8_t *msg,
                       size_t msg_len,
                       const uint8_t *ad,
                       size_t ad_len,
                       const uint8_t *pubnonce,
                       const uint8_t *secnonce) {
  int res = 0;
  aegis256_ctx *ctx = (aegis256_ctx *)aead_key;
  uint8_t *tag = ct + msg_len;
  res |= aegis256_encrypt_detached(ct, tag, aegis256_tag_len, msg, msg_len, ad,
                                   ad_len, pubnonce, ctx->key);
  return (res == 0);
}

int aead_aegis256_open(AeadKey *aead_key,
                       uint8_t *msg,
                       uint8_t *secnonce,
                       const uint8_t *ct,
                       size_t ct_len,
                       const uint8_t *ad,
                       size_t ad_len,
                       const uint8_t *pubnonce) {
  int res = 0;
  aegis256_ctx *ctx = (aegis256_ctx *)aead_key;
  const uint8_t *tag = ct + ct_len - aegis256_tag_len;
  size_t ctcore_len = ct_len - aegis256_tag_len;
  res |= aegis256_decrypt_detached(msg, ct, ctcore_len, tag, aegis256_tag_len,
                                   ad, ad_len, pubnonce, ctx->key);
  return (res == 0);
}

static const Aead aegis256 = {"Aead-Aegis256",
                              aead_aegis256_key_len,
                              aead_aegis256_pubnonce_len,
                              aead_aegis256_secnonce_len,
                              aead_aegis256_overhead,
                              aead_aegis256_init,
                              aead_aegis256_seal,
                              aead_aegis256_open,
                              NULL,
                              NULL};

const Aead *Aead_aegis256() {
  return &aegis256;
}