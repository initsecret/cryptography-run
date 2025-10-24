#include <assert.h>

#include <cryptography-run/aead.h>

// #include <openssl/core_names.h>
// #include <openssl/evp.h>
// #include <openssl/hmac.h>

#include <openssl/aead.h>

/* ------------------------------------------------------------------------- */
/* Aead interface for ChaCha20/Poly1305                                      */

static const uint8_t aead_chapoly_key_len = 32;
static const uint8_t aead_chapoly_pubnonce_len = 12;
static const uint8_t aead_chapoly_secnonce_len = 0;
static const uint8_t aead_chapoly_overhead = 16;

typedef struct {
  EVP_AEAD_CTX evpctx;
} bssl_ctx;

static int aead_chapoly_init(AeadKey *aead_key,
                             const uint8_t *key,
                             size_t key_len) {
  bssl_ctx *ctx = (bssl_ctx *)aead_key;
  assert(key_len == aead_chapoly_key_len);
  int ret = 1;
  ret &= EVP_AEAD_CTX_init(&ctx->evpctx, EVP_aead_chacha20_poly1305(), key,
                           key_len, aead_chapoly_overhead, NULL);
  return ret;
}

static int aead_chapoly_seal_scatter(AeadKey *aead_key,
                                     uint8_t *ctcore,
                                     uint8_t *tag,
                                     const uint8_t *msg,
                                     size_t msg_len,
                                     const uint8_t *ad,
                                     size_t ad_len,
                                     const uint8_t *pubnonce,
                                     const uint8_t *secnonce) {
  bssl_ctx *ctx = (bssl_ctx *)aead_key;
  int ret = 1;
  size_t out_tag_len = 0;
  ret &= EVP_AEAD_CTX_seal_scatter(
      &ctx->evpctx, ctcore, tag, &out_tag_len, aead_chapoly_overhead, pubnonce,
      aead_chapoly_pubnonce_len, msg, msg_len, NULL, 0, ad, ad_len);
  return ret;
}

// UNIMPLEMENTED
// static int aead_chapoly_partial_open(AeadKey *aead_key,
//                                uint8_t *msg,
//                                uint8_t *tag,
//                                const uint8_t *ctcore,
//                                size_t ctcore_len,
//                                const uint8_t *ad,
//                                size_t ad_len,
//                                const uint8_t *nonce) {
//                                 return 0;
// }

static int aead_chapoly_seal(AeadKey *aead_key,
                             uint8_t *ct,
                             const uint8_t *msg,
                             size_t msg_len,
                             const uint8_t *ad,
                             size_t ad_len,
                             const uint8_t *pubnonce,
                             const uint8_t *secnonce) {
  uint8_t *ctcore = ct;
  uint8_t *tag = ct + msg_len;
  return aead_chapoly_seal_scatter(aead_key, ctcore, tag, msg, msg_len, ad,
                                   ad_len, pubnonce, secnonce);
}

static int aead_chapoly_open(AeadKey *aead_key,
                             uint8_t *msg,
                             uint8_t *secnonce,
                             const uint8_t *ct,
                             size_t ct_len,
                             const uint8_t *ad,
                             size_t ad_len,
                             const uint8_t *pubnonce) {
  const uint8_t *ctcore = ct;
  size_t ctcore_len = ct_len - aead_chapoly_overhead;
  const uint8_t *tag = ct + ctcore_len;

  bssl_ctx *ctx = (bssl_ctx *)aead_key;
  int ret = 1;
  ret &= EVP_AEAD_CTX_open_gather(&ctx->evpctx, msg, pubnonce,
                                  aead_chapoly_pubnonce_len, ctcore, ctcore_len,
                                  tag, aead_chapoly_overhead, ad, ad_len);
  return ret;
}

static const Aead chapoly = {
    "BSSL-ChaCha20/Poly1305",  aead_chapoly_key_len,
    aead_chapoly_pubnonce_len, aead_chapoly_secnonce_len,
    aead_chapoly_overhead,     aead_chapoly_init,
    aead_chapoly_seal,         aead_chapoly_open,
    aead_chapoly_seal_scatter, NULL};

const Aead *Aead_bssl_chapoly() {
  return &chapoly;
}

/* ------------------------------------------------------------------------- */
/* Aead interface for XChaCha20/Poly1305                                      */

static const uint8_t aead_xchapoly_key_len = 32;
static const uint8_t aead_xchapoly_pubnonce_len = 24;
static const uint8_t aead_xchapoly_secnonce_len = 0;
static const uint8_t aead_xchapoly_overhead = 16;

static int aead_xchapoly_init(AeadKey *aead_key,
                              const uint8_t *key,
                              size_t key_len) {
  bssl_ctx *ctx = (bssl_ctx *)aead_key;
  assert(key_len == aead_xchapoly_key_len);
  int ret = 1;
  ret &= EVP_AEAD_CTX_init(&ctx->evpctx, EVP_aead_xchacha20_poly1305(), key,
                           key_len, aead_xchapoly_overhead, NULL);
  return ret;
}

static int aead_xchapoly_seal_scatter(AeadKey *aead_key,
                                      uint8_t *ctcore,
                                      uint8_t *tag,
                                      const uint8_t *msg,
                                      size_t msg_len,
                                      const uint8_t *ad,
                                      size_t ad_len,
                                      const uint8_t *pubnonce,
                                      const uint8_t *secnonce) {
  bssl_ctx *ctx = (bssl_ctx *)aead_key;
  int ret = 1;
  size_t out_tag_len = 0;
  ret &= EVP_AEAD_CTX_seal_scatter(
      &ctx->evpctx, ctcore, tag, &out_tag_len, aead_xchapoly_overhead, pubnonce,
      aead_xchapoly_pubnonce_len, msg, msg_len, NULL, 0, ad, ad_len);
  return ret;
}

static int aead_xchapoly_seal(AeadKey *aead_key,
                              uint8_t *ct,
                              const uint8_t *msg,
                              size_t msg_len,
                              const uint8_t *ad,
                              size_t ad_len,
                              const uint8_t *pubnonce,
                              const uint8_t *secnonce) {
  uint8_t *ctcore = ct;
  uint8_t *tag = ct + msg_len;
  return aead_xchapoly_seal_scatter(aead_key, ctcore, tag, msg, msg_len, ad,
                                    ad_len, pubnonce, secnonce);
}

static int aead_xchapoly_open(AeadKey *aead_key,
                              uint8_t *msg,
                              uint8_t *secnonce,
                              const uint8_t *ct,
                              size_t ct_len,
                              const uint8_t *ad,
                              size_t ad_len,
                              const uint8_t *pubnonce) {
  const uint8_t *ctcore = ct;
  size_t ctcore_len = ct_len - aead_xchapoly_overhead;
  const uint8_t *tag = ct + ctcore_len;

  bssl_ctx *ctx = (bssl_ctx *)aead_key;
  int ret = 1;
  ret &= EVP_AEAD_CTX_open_gather(
      &ctx->evpctx, msg, pubnonce, aead_xchapoly_pubnonce_len, ctcore,
      ctcore_len, tag, aead_xchapoly_overhead, ad, ad_len);
  return ret;
}

static const Aead xchapoly = {
    "BSSL-XChaCha20/Poly1305",  aead_xchapoly_key_len,
    aead_xchapoly_pubnonce_len, aead_xchapoly_secnonce_len,
    aead_xchapoly_overhead,     aead_xchapoly_init,
    aead_xchapoly_seal,         aead_xchapoly_open,
    aead_xchapoly_seal_scatter, NULL};

const Aead *Aead_bssl_xchapoly() {
  return &xchapoly;
}

/* ------------------------------------------------------------------------- */
/* Aead interface for AES128/256-GCM */

static const uint8_t aead_aes128gcm_key_len = 16;
static const uint8_t aead_aes256gcm_key_len = 32;
static const uint8_t aead_aesgcm_pubnonce_len = 12;
static const uint8_t aead_aesgcm_secnonce_len = 0;
static const uint8_t aead_aesgcm_overhead = 16;

static int aead_aes128gcm_init(AeadKey *aead_key,
                               const uint8_t *key,
                               size_t key_len) {
  bssl_ctx *ctx = (bssl_ctx *)aead_key;
  assert(key_len == aead_aes128gcm_key_len);
  int ret = 1;
  ret &= EVP_AEAD_CTX_init(&ctx->evpctx, EVP_aead_aes_128_gcm(), key, key_len,
                           aead_aesgcm_overhead, NULL);
  return ret;
}

static int aead_aes256gcm_init(AeadKey *aead_key,
                               const uint8_t *key,
                               size_t key_len) {
  bssl_ctx *ctx = (bssl_ctx *)aead_key;
  assert(key_len == aead_aes256gcm_key_len);
  int ret = 1;
  ret &= EVP_AEAD_CTX_init(&ctx->evpctx, EVP_aead_aes_256_gcm(), key, key_len,
                           aead_aesgcm_overhead, NULL);
  return ret;
}

static int aead_aesgcm_seal(AeadKey *aead_key,
                            uint8_t *ct,
                            const uint8_t *msg,
                            size_t msg_len,
                            const uint8_t *ad,
                            size_t ad_len,
                            const uint8_t *nonce,
                            const uint8_t *secnonce) {
  bssl_ctx *ctx = (bssl_ctx *)aead_key;
  int ret = 1;
  size_t out_len = 0;
  const size_t max_out_len = msg_len + aead_aesgcm_overhead;
  ret &= EVP_AEAD_CTX_seal(&ctx->evpctx, ct, &out_len, max_out_len, nonce,
                           aead_aesgcm_pubnonce_len, msg, msg_len, ad, ad_len);
  return ret;
}

static int aead_aesgcm_open(AeadKey *aead_key,
                            uint8_t *msg,
                            uint8_t *secnonce,
                            const uint8_t *ct,
                            size_t ct_len,
                            const uint8_t *ad,
                            size_t ad_len,
                            const uint8_t *nonce) {
  bssl_ctx *ctx = (bssl_ctx *)aead_key;
  int ret = 1;
  size_t out_len = 0;
  const size_t max_out_len = ct_len - aead_aesgcm_overhead;
  ret &= EVP_AEAD_CTX_open(&ctx->evpctx, msg, &out_len, max_out_len, nonce,
                           aead_aesgcm_pubnonce_len, ct, ct_len, ad, ad_len);
  return ret;
}

static const Aead aes128gcm = {"BSSL-AES128-GCM",
                               aead_aes128gcm_key_len,
                               aead_aesgcm_pubnonce_len,
                               aead_aesgcm_secnonce_len,
                               aead_aesgcm_overhead,
                               aead_aes128gcm_init,
                               aead_aesgcm_seal,
                               aead_aesgcm_open,
                               NULL,
                               NULL};

const Aead *Aead_bssl_aes128_gcm() {
  return &aes128gcm;
}

static const Aead aes256gcm = {"BSSL-AES256-GCM",
                               aead_aes256gcm_key_len,
                               aead_aesgcm_pubnonce_len,
                               aead_aesgcm_secnonce_len,
                               aead_aesgcm_overhead,
                               aead_aes256gcm_init,
                               aead_aesgcm_seal,
                               aead_aesgcm_open,
                               NULL,
                               NULL};

const Aead *Aead_bssl_aes256_gcm() {
  return &aes256gcm;
}