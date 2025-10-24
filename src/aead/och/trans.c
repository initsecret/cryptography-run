#include "trans.h"

#include <cryptography-run/aead.h>
#include <cryptography-run/base.h>

#ifdef __x86_64__

/* ------------------------------------------------------------------------- */
/* Aead interface for CTY/XtH-<Hash>-AES256-GCM                              */

static const uint8_t aead_trans_aes256_gcm_key_len = 32;
static const uint8_t aead_trans_aes256_gcm_pubnonce_len = 12;
static const uint8_t aead_trans_aes256_gcm_secnonce_len = 0;
static const uint8_t aead_trans_aes256_gcm_overhead = 32;

static const uint8_t label_cty_kg = 0xa0;
static const uint8_t label_xth_kg = 0xb0;

typedef struct {
  // 256 bytes
  alignas(32) HashState h_ctx;
  // haberdashery_aes256gcm_skylake_t
  // alignas(32) uint8_t inner_ctx[336];
  alignas(32) uint8_t inner_ctx[512];
} trans_aes256_gcm_ctx;

int aead_trans_aes256_gcm_init(const Hash *hash,
                               const uint8_t label_kg,
                               AeadKey *aead_key,
                               const uint8_t *key,
                               size_t key_len) {
  trans_aes256_gcm_ctx *ctx = (trans_aes256_gcm_ctx *)aead_key;
  int ret = 1;
  assert(key_len == 32);
  // derive subkey and init aead
  uint8_t subkey[32] = {0};
  ret &= hash->keyed_hash(key, key_len, subkey, 32, &label_kg, 1);
  ret &= Aead_aes256_gcm()->init((AeadKey *)ctx->inner_ctx, key,
                                 Aead_aes256_gcm()->key_len);
  // precompute keyed hash state
  ret &= hash->init(&ctx->h_ctx, key, key_len, 32);
  return ret;
}

int aead_trans_aes256_gcm_seal(const Hash *hash,
                               trans_tag tag_fn,
                               AeadKey *aead_key,
                               uint8_t *ct,
                               const uint8_t *msg,
                               size_t msg_len,
                               const uint8_t *ad,
                               size_t ad_len,
                               const uint8_t *pubnonce,
                               const uint8_t *secnonce) {
  int ret = 1;
  trans_aes256_gcm_ctx *ctx = (trans_aes256_gcm_ctx *)aead_key;

  // encrypt with no ad to ct and inner_tag
  uint8_t inner_tag[16] = {0};
  ret &= Aead_aes256_gcm()->seal_scatter((AeadKey *)ctx->inner_ctx, ct,
                                         inner_tag, msg, msg_len, NULL, 0,
                                         pubnonce, secnonce);

  // hash to tag
  uint8_t *tag = ct + msg_len;
  (*tag_fn)(hash, &ctx->h_ctx, tag, ad, ad_len, pubnonce,
            aead_trans_aes256_gcm_pubnonce_len, inner_tag, 16);
  return ret;
}

int aead_trans_aes256_gcm_open(const Hash *hash,
                               trans_tag tag_fn,
                               AeadKey *aead_key,
                               uint8_t *msg,
                               uint8_t *secnonce,
                               const uint8_t *ct,
                               size_t ct_len,
                               const uint8_t *ad,
                               size_t ad_len,
                               const uint8_t *pubnonce) {
  int ret = 1;
  trans_aes256_gcm_ctx *ctx = (trans_aes256_gcm_ctx *)aead_key;

  // partial decrypt with no ad to msg and inner_tag
  uint8_t inner_tag[16] = {0};
  const uint8_t *ctcore = ct;
  size_t ctcore_len = ct_len - aead_trans_aes256_gcm_overhead;
  ret &= Aead_aes256_gcm()->partial_open((AeadKey *)ctx->inner_ctx, msg,
                                         secnonce, inner_tag, ctcore,
                                         ctcore_len, NULL, 0, pubnonce);

  // hash to tag and compare
  uint8_t expected_tag[32] = {0};
  (*tag_fn)(hash, &ctx->h_ctx, expected_tag, ad, ad_len, pubnonce,
            aead_trans_aes256_gcm_pubnonce_len, inner_tag, 16);
  const uint8_t *given_tag = ct + ct_len - aead_trans_aes256_gcm_overhead;
  ret &= constant_time_compare(expected_tag, given_tag, 32);
  return ret;
}

/* ------------------------------------------------------------------------- */
/* Aead interface for CTY-SHA256-AES256-GCM                         */

int aead_cty_sha256_aes256_gcm_init(AeadKey *aead_key,
                                    const uint8_t *key,
                                    size_t key_len) {
  return aead_trans_aes256_gcm_init(Hash_sha256(), label_cty_kg, aead_key, key,
                                    key_len);
}

int aead_cty_sha256_aes256_gcm_seal(AeadKey *aead_key,
                                    uint8_t *ct,
                                    const uint8_t *msg,
                                    size_t msg_len,
                                    const uint8_t *ad,
                                    size_t ad_len,
                                    const uint8_t *pubnonce,
                                    const uint8_t *secnonce) {
  return aead_trans_aes256_gcm_seal(Hash_sha256(), Hash_cty_tag, aead_key, ct,
                                    msg, msg_len, ad, ad_len, pubnonce,
                                    secnonce);
}

int aead_cty_sha256_aes256_gcm_open(AeadKey *aead_key,
                                    uint8_t *msg,
                                    uint8_t *secnonce,
                                    const uint8_t *ct,
                                    size_t ct_len,
                                    const uint8_t *ad,
                                    size_t ad_len,
                                    const uint8_t *nonce) {
  return aead_trans_aes256_gcm_open(Hash_sha256(), Hash_cty_tag, aead_key, msg,
                                    secnonce, ct, ct_len, ad, ad_len, nonce);
}

static const Aead cty_sha256_aes256_gcm = {"CTY-SHA256-AES256-GCM",
                                           aead_trans_aes256_gcm_key_len,
                                           aead_trans_aes256_gcm_pubnonce_len,
                                           aead_trans_aes256_gcm_secnonce_len,
                                           aead_trans_aes256_gcm_overhead,
                                           aead_cty_sha256_aes256_gcm_init,
                                           aead_cty_sha256_aes256_gcm_seal,
                                           aead_cty_sha256_aes256_gcm_open,
                                           NULL,
                                           NULL};

const Aead *Aead_cty_sha256_aes256_gcm() {
  return &cty_sha256_aes256_gcm;
}

/* ------------------------------------------------------------------------- */
/* Aead interface for XtH-SHA256-AES256-GCM                         */

int aead_xth_sha256_aes256_gcm_init(AeadKey *aead_key,
                                    const uint8_t *key,
                                    size_t key_len) {
  return aead_trans_aes256_gcm_init(Hash_sha256(), label_xth_kg, aead_key, key,
                                    key_len);
}

int aead_xth_sha256_aes256_gcm_seal(AeadKey *aead_key,
                                    uint8_t *ct,
                                    const uint8_t *msg,
                                    size_t msg_len,
                                    const uint8_t *ad,
                                    size_t ad_len,
                                    const uint8_t *pubnonce,
                                    const uint8_t *secnonce) {
  return aead_trans_aes256_gcm_seal(Hash_sha256(), Hash_xth_tag, aead_key, ct,
                                    msg, msg_len, ad, ad_len, pubnonce,
                                    secnonce);
}

int aead_xth_sha256_aes256_gcm_open(AeadKey *aead_key,
                                    uint8_t *msg,
                                    uint8_t *secnonce,
                                    const uint8_t *ct,
                                    size_t ct_len,
                                    const uint8_t *ad,
                                    size_t ad_len,
                                    const uint8_t *nonce) {
  return aead_trans_aes256_gcm_open(Hash_sha256(), Hash_xth_tag, aead_key, msg,
                                    secnonce, ct, ct_len, ad, ad_len, nonce);
}

static const Aead xth_sha256_aes256_gcm = {"XtH-SHA256-AES256-GCM",
                                           aead_trans_aes256_gcm_key_len,
                                           aead_trans_aes256_gcm_pubnonce_len,
                                           aead_trans_aes256_gcm_secnonce_len,
                                           aead_trans_aes256_gcm_overhead,
                                           aead_xth_sha256_aes256_gcm_init,
                                           aead_xth_sha256_aes256_gcm_seal,
                                           aead_xth_sha256_aes256_gcm_open,
                                           NULL,
                                           NULL};

const Aead *Aead_xth_sha256_aes256_gcm() {
  return &xth_sha256_aes256_gcm;
}

/* -------------------------------------------------------------------------- */
/* Aead interface for CTY-Blake2b-AES256-GCM                                  */

int aead_cty_blake2b_aes256_gcm_init(AeadKey *aead_key,
                                     const uint8_t *key,
                                     size_t key_len) {
  return aead_trans_aes256_gcm_init(Hash_blake2b(), label_cty_kg, aead_key, key,
                                    key_len);
}

int aead_cty_blake2b_aes256_gcm_seal(AeadKey *aead_key,
                                     uint8_t *ct,
                                     const uint8_t *msg,
                                     size_t msg_len,
                                     const uint8_t *ad,
                                     size_t ad_len,
                                     const uint8_t *nonce,
                                     const uint8_t *secnonce) {
  return aead_trans_aes256_gcm_seal(Hash_blake2b(), Hash_cty_tag, aead_key, ct,
                                    msg, msg_len, ad, ad_len, nonce, secnonce);
}

int aead_cty_blake2b_aes256_gcm_open(AeadKey *aead_key,
                                     uint8_t *msg,
                                     uint8_t *secnonce,
                                     const uint8_t *ct,
                                     size_t ct_len,
                                     const uint8_t *ad,
                                     size_t ad_len,
                                     const uint8_t *nonce) {
  return aead_trans_aes256_gcm_open(Hash_blake2b(), Hash_cty_tag, aead_key, msg,
                                    secnonce, ct, ct_len, ad, ad_len, nonce);
}

static const Aead cty_blake2b_aes256_gcm = {"CTY-Blake2b-AES256-GCM",
                                            aead_trans_aes256_gcm_key_len,
                                            aead_trans_aes256_gcm_pubnonce_len,
                                            aead_trans_aes256_gcm_secnonce_len,
                                            aead_trans_aes256_gcm_overhead,
                                            aead_cty_blake2b_aes256_gcm_init,
                                            aead_cty_blake2b_aes256_gcm_seal,
                                            aead_cty_blake2b_aes256_gcm_open,
                                            NULL,
                                            NULL};

const Aead *Aead_cty_blake2b_aes256_gcm() {
  return &cty_blake2b_aes256_gcm;
}

/* -------------------------------------------------------------------------- */
/* Aead interface for XtH-Blake2b-AES256-GCM                                  */

int aead_xth_blake2b_aes256_gcm_init(AeadKey *aead_key,
                                     const uint8_t *key,
                                     size_t key_len) {
  return aead_trans_aes256_gcm_init(Hash_blake2b(), label_xth_kg, aead_key, key,
                                    key_len);
}

int aead_xth_blake2b_aes256_gcm_seal(AeadKey *aead_key,
                                     uint8_t *ct,
                                     const uint8_t *msg,
                                     size_t msg_len,
                                     const uint8_t *ad,
                                     size_t ad_len,
                                     const uint8_t *nonce,
                                     const uint8_t *secnonce) {
  return aead_trans_aes256_gcm_seal(Hash_blake2b(), Hash_xth_tag, aead_key, ct,
                                    msg, msg_len, ad, ad_len, nonce, secnonce);
}

int aead_xth_blake2b_aes256_gcm_open(AeadKey *aead_key,
                                     uint8_t *msg,
                                     uint8_t *secnonce,
                                     const uint8_t *ct,
                                     size_t ct_len,
                                     const uint8_t *ad,
                                     size_t ad_len,
                                     const uint8_t *nonce) {
  return aead_trans_aes256_gcm_open(Hash_blake2b(), Hash_xth_tag, aead_key, msg,
                                    secnonce, ct, ct_len, ad, ad_len, nonce);
}

static const Aead xth_blake2b_aes256_gcm = {"XtH-Blake2b-AES256-GCM",
                                            aead_trans_aes256_gcm_key_len,
                                            aead_trans_aes256_gcm_pubnonce_len,
                                            aead_trans_aes256_gcm_secnonce_len,
                                            aead_trans_aes256_gcm_overhead,
                                            aead_xth_blake2b_aes256_gcm_init,
                                            aead_xth_blake2b_aes256_gcm_seal,
                                            aead_xth_blake2b_aes256_gcm_open,
                                            NULL,
                                            NULL};

const Aead *Aead_xth_blake2b_aes256_gcm() {
  return &xth_blake2b_aes256_gcm;
}

/* -------------------------------------------------------------------------- */
/* Aead interface for CTY-sha3_256-AES256-GCM */

int aead_cty_sha3_256_aes256_gcm_init(AeadKey *aead_key,
                                      const uint8_t *key,
                                      size_t key_len) {
  return aead_trans_aes256_gcm_init(Hash_sha3_256(), label_cty_kg, aead_key,
                                    key, key_len);
}

int aead_cty_sha3_256_aes256_gcm_seal(AeadKey *aead_key,
                                      uint8_t *ct,
                                      const uint8_t *msg,
                                      size_t msg_len,
                                      const uint8_t *ad,
                                      size_t ad_len,
                                      const uint8_t *nonce,
                                      const uint8_t *secnonce) {
  return aead_trans_aes256_gcm_seal(Hash_sha3_256(), Hash_cty_tag, aead_key, ct,
                                    msg, msg_len, ad, ad_len, nonce, secnonce);
}

int aead_cty_sha3_256_aes256_gcm_open(AeadKey *aead_key,
                                      uint8_t *msg,
                                      uint8_t *secnonce,
                                      const uint8_t *ct,
                                      size_t ct_len,
                                      const uint8_t *ad,
                                      size_t ad_len,
                                      const uint8_t *nonce) {
  return aead_trans_aes256_gcm_open(Hash_sha3_256(), Hash_cty_tag, aead_key,
                                    msg, secnonce, ct, ct_len, ad, ad_len,
                                    nonce);
}

static const Aead cty_sha3_256_aes256_gcm = {"CTY-SHA3-256-AES256-GCM",
                                             aead_trans_aes256_gcm_key_len,
                                             aead_trans_aes256_gcm_pubnonce_len,
                                             aead_trans_aes256_gcm_secnonce_len,
                                             aead_trans_aes256_gcm_overhead,
                                             aead_cty_sha3_256_aes256_gcm_init,
                                             aead_cty_sha3_256_aes256_gcm_seal,
                                             aead_cty_sha3_256_aes256_gcm_open,
                                             NULL,
                                             NULL};

const Aead *Aead_cty_sha3_256_aes256_gcm() {
  return &cty_sha3_256_aes256_gcm;
}

/* -------------------------------------------------------------------------- */
/* Aead interface for XtH-sha3_256-AES256-GCM */

int aead_xth_sha3_256_aes256_gcm_init(AeadKey *aead_key,
                                      const uint8_t *key,
                                      size_t key_len) {
  return aead_trans_aes256_gcm_init(Hash_sha3_256(), label_xth_kg, aead_key,
                                    key, key_len);
}

int aead_xth_sha3_256_aes256_gcm_seal(AeadKey *aead_key,
                                      uint8_t *ct,
                                      const uint8_t *msg,
                                      size_t msg_len,
                                      const uint8_t *ad,
                                      size_t ad_len,
                                      const uint8_t *nonce,
                                      const uint8_t *secnonce) {
  return aead_trans_aes256_gcm_seal(Hash_sha3_256(), Hash_xth_tag, aead_key, ct,
                                    msg, msg_len, ad, ad_len, nonce, secnonce);
}

int aead_xth_sha3_256_aes256_gcm_open(AeadKey *aead_key,
                                      uint8_t *msg,
                                      uint8_t *secnonce,
                                      const uint8_t *ct,
                                      size_t ct_len,
                                      const uint8_t *ad,
                                      size_t ad_len,
                                      const uint8_t *nonce) {
  return aead_trans_aes256_gcm_open(Hash_sha3_256(), Hash_xth_tag, aead_key,
                                    msg, secnonce, ct, ct_len, ad, ad_len,
                                    nonce);
}

static const Aead xth_sha3_256_aes256_gcm = {"XtH-SHA3-256-AES256-GCM",
                                             aead_trans_aes256_gcm_key_len,
                                             aead_trans_aes256_gcm_pubnonce_len,
                                             aead_trans_aes256_gcm_secnonce_len,
                                             aead_trans_aes256_gcm_overhead,
                                             aead_xth_sha3_256_aes256_gcm_init,
                                             aead_xth_sha3_256_aes256_gcm_seal,
                                             aead_xth_sha3_256_aes256_gcm_open,
                                             NULL,
                                             NULL};

const Aead *Aead_xth_sha3_256_aes256_gcm() {
  return &xth_sha3_256_aes256_gcm;
}

/* -------------------------------------------------------------------------- */
/* Aead interface for CTY-ascon256-AES256-GCM */

int aead_cty_ascon256_aes256_gcm_init(AeadKey *aead_key,
                                      const uint8_t *key,
                                      size_t key_len) {
  return aead_trans_aes256_gcm_init(Hash_ascon256(), label_cty_kg, aead_key,
                                    key, key_len);
}

int aead_cty_ascon256_aes256_gcm_seal(AeadKey *aead_key,
                                      uint8_t *ct,
                                      const uint8_t *msg,
                                      size_t msg_len,
                                      const uint8_t *ad,
                                      size_t ad_len,
                                      const uint8_t *nonce,
                                      const uint8_t *secnonce) {
  return aead_trans_aes256_gcm_seal(Hash_ascon256(), Hash_cty_tag, aead_key, ct,
                                    msg, msg_len, ad, ad_len, nonce, secnonce);
}

int aead_cty_ascon256_aes256_gcm_open(AeadKey *aead_key,
                                      uint8_t *msg,
                                      uint8_t *secnonce,
                                      const uint8_t *ct,
                                      size_t ct_len,
                                      const uint8_t *ad,
                                      size_t ad_len,
                                      const uint8_t *nonce) {
  return aead_trans_aes256_gcm_open(Hash_ascon256(), Hash_cty_tag, aead_key,
                                    msg, secnonce, ct, ct_len, ad, ad_len,
                                    nonce);
}

static const Aead cty_ascon256_aes256_gcm = {"CTY-AsconHash256-AES256-GCM",
                                             aead_trans_aes256_gcm_key_len,
                                             aead_trans_aes256_gcm_pubnonce_len,
                                             aead_trans_aes256_gcm_secnonce_len,
                                             aead_trans_aes256_gcm_overhead,
                                             aead_cty_ascon256_aes256_gcm_init,
                                             aead_cty_ascon256_aes256_gcm_seal,
                                             aead_cty_ascon256_aes256_gcm_open,
                                             NULL,
                                             NULL};

const Aead *Aead_cty_ascon256_aes256_gcm() {
  return &cty_ascon256_aes256_gcm;
}

/* -------------------------------------------------------------------------- */
/* Aead interface for XtH-ascon256-AES256-GCM */

int aead_xth_ascon256_aes256_gcm_init(AeadKey *aead_key,
                                      const uint8_t *key,
                                      size_t key_len) {
  return aead_trans_aes256_gcm_init(Hash_ascon256(), label_xth_kg, aead_key,
                                    key, key_len);
}

int aead_xth_ascon256_aes256_gcm_seal(AeadKey *aead_key,
                                      uint8_t *ct,
                                      const uint8_t *msg,
                                      size_t msg_len,
                                      const uint8_t *ad,
                                      size_t ad_len,
                                      const uint8_t *nonce,
                                      const uint8_t *secnonce) {
  return aead_trans_aes256_gcm_seal(Hash_ascon256(), Hash_xth_tag, aead_key, ct,
                                    msg, msg_len, ad, ad_len, nonce, secnonce);
}

int aead_xth_ascon256_aes256_gcm_open(AeadKey *aead_key,
                                      uint8_t *msg,
                                      uint8_t *secnonce,
                                      const uint8_t *ct,
                                      size_t ct_len,
                                      const uint8_t *ad,
                                      size_t ad_len,
                                      const uint8_t *nonce) {
  return aead_trans_aes256_gcm_open(Hash_ascon256(), Hash_xth_tag, aead_key,
                                    msg, secnonce, ct, ct_len, ad, ad_len,
                                    nonce);
}

static const Aead xth_ascon256_aes256_gcm = {"XtH-AsconHash256-AES256-GCM",
                                             aead_trans_aes256_gcm_key_len,
                                             aead_trans_aes256_gcm_pubnonce_len,
                                             aead_trans_aes256_gcm_secnonce_len,
                                             aead_trans_aes256_gcm_overhead,
                                             aead_xth_ascon256_aes256_gcm_init,
                                             aead_xth_ascon256_aes256_gcm_seal,
                                             aead_xth_ascon256_aes256_gcm_open,
                                             NULL,
                                             NULL};

const Aead *Aead_xth_ascon256_aes256_gcm() {
  return &xth_ascon256_aes256_gcm;
}

#endif

/* -------------------------------------------------------------------------- */
/* Aead interface for CTY-areion512sponge-AES256-GCM */

#if defined(CR_HAS_AREION) && defined(__x86_64__)

int aead_cty_areion512sponge_aes256_gcm_init(AeadKey *aead_key,
                                             const uint8_t *key,
                                             size_t key_len) {
  return aead_trans_aes256_gcm_init(Hash_Areion512Sponge(), label_cty_kg,
                                    aead_key, key, key_len);
}

int aead_cty_areion512sponge_aes256_gcm_seal(AeadKey *aead_key,
                                             uint8_t *ct,
                                             const uint8_t *msg,
                                             size_t msg_len,
                                             const uint8_t *ad,
                                             size_t ad_len,
                                             const uint8_t *nonce,
                                             const uint8_t *secnonce) {
  return aead_trans_aes256_gcm_seal(Hash_Areion512Sponge(), Hash_cty_tag,
                                    aead_key, ct, msg, msg_len, ad, ad_len,
                                    nonce, secnonce);
}

int aead_cty_areion512sponge_aes256_gcm_open(AeadKey *aead_key,
                                             uint8_t *msg,
                                             uint8_t *secnonce,
                                             const uint8_t *ct,
                                             size_t ct_len,
                                             const uint8_t *ad,
                                             size_t ad_len,
                                             const uint8_t *nonce) {
  return aead_trans_aes256_gcm_open(Hash_Areion512Sponge(), Hash_cty_tag,
                                    aead_key, msg, secnonce, ct, ct_len, ad,
                                    ad_len, nonce);
}

static const Aead cty_areion512sponge_aes256_gcm = {
    "CTY-Areion512Sponge-AES256-GCM",
    aead_trans_aes256_gcm_key_len,
    aead_trans_aes256_gcm_pubnonce_len,
    aead_trans_aes256_gcm_secnonce_len,
    aead_trans_aes256_gcm_overhead,
    aead_cty_areion512sponge_aes256_gcm_init,
    aead_cty_areion512sponge_aes256_gcm_seal,
    aead_cty_areion512sponge_aes256_gcm_open,
    NULL,
    NULL};

const Aead *Aead_cty_areion512sponge_aes256_gcm() {
  return &cty_areion512sponge_aes256_gcm;
}

/* -------------------------------------------------------------------------- */
/* Aead interface for XtH-areion512sponge-AES256-GCM */

int aead_xth_areion512sponge_aes256_gcm_init(AeadKey *aead_key,
                                             const uint8_t *key,
                                             size_t key_len) {
  return aead_trans_aes256_gcm_init(Hash_Areion512Sponge(), label_xth_kg,
                                    aead_key, key, key_len);
}

int aead_xth_areion512sponge_aes256_gcm_seal(AeadKey *aead_key,
                                             uint8_t *ct,
                                             const uint8_t *msg,
                                             size_t msg_len,
                                             const uint8_t *ad,
                                             size_t ad_len,
                                             const uint8_t *nonce,
                                             const uint8_t *secnonce) {
  return aead_trans_aes256_gcm_seal(Hash_Areion512Sponge(), Hash_xth_tag,
                                    aead_key, ct, msg, msg_len, ad, ad_len,
                                    nonce, secnonce);
}

int aead_xth_areion512sponge_aes256_gcm_open(AeadKey *aead_key,
                                             uint8_t *msg,
                                             uint8_t *secnonce,
                                             const uint8_t *ct,
                                             size_t ct_len,
                                             const uint8_t *ad,
                                             size_t ad_len,
                                             const uint8_t *nonce) {
  return aead_trans_aes256_gcm_open(Hash_Areion512Sponge(), Hash_xth_tag,
                                    aead_key, msg, secnonce, ct, ct_len, ad,
                                    ad_len, nonce);
}

static const Aead xth_areion512sponge_aes256_gcm = {
    "XtH-Areion512Sponge-AES256-GCM",
    aead_trans_aes256_gcm_key_len,
    aead_trans_aes256_gcm_pubnonce_len,
    aead_trans_aes256_gcm_secnonce_len,
    aead_trans_aes256_gcm_overhead,
    aead_xth_areion512sponge_aes256_gcm_init,
    aead_xth_areion512sponge_aes256_gcm_seal,
    aead_xth_areion512sponge_aes256_gcm_open,
    NULL,
    NULL};

const Aead *Aead_xth_areion512sponge_aes256_gcm() {
  return &xth_areion512sponge_aes256_gcm;
}

#endif  // defined(CR_HAS_AREION) && defined(__x86_64__)
