/*
    OCH with RRBlake2b-MEM

    :copyright: (c) 2024 by OCH authors
    :license: Creative Commons CC0 1.0
*/
/*
    (Previous copyright statement)

    OPP - MEM AEAD source code package

    :copyright: (c) 2015 by Philipp Jovanovic and Samuel Neves
    :license: Creative Commons CC0 1.0
*/
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <immintrin.h>

#define OPP_W 64
#define OPP_R 4
#define OPP_T (OPP_W * 4)  // 256 bit = 32 byte tag
#define OPP_B 1024         // 1024 bit = 128 byte permutation

#include "v0.h"
#include "v1.h"
// #include "v2.h"
#include "v4.h"

/* this is x86, so we can just memcpy */
/*
static uint64_t load64(const void * in) {
  uint64_t x;
  memcpy(&x, in, sizeof x);
  return x;
}
*/

static void opp_pad(unsigned char *out, const void *in, size_t inlen) {
  memset(out, 0, BYTES(OPP_B));
  memcpy(out, in, inlen);
  out[inlen] = 0x01;
}

static void opp_kdf(uint64_t *Ka,
                    uint64_t *Ke,
                    const uint8_t *k,
                    const uint8_t *n) {
  __m256i B[4];
  B[0] = LOADU256(n);
  B[1] = _mm256_setzero_si256();
  B[2] = _mm256_set_epi64x(OPP_T, OPP_R, 0, 0);
  B[3] = LOADU256(k);

  V1_PERMUTE_F(B);

  memcpy(Ka, B, sizeof(B));
  memcpy(Ke, B, sizeof(B));
  V1_GAMMA_UPDATE(Ke);
}

static void opp_hash_data(__m256i T[4],
                          const uint8_t *h,
                          size_t hlen,
                          uint64_t L[16 + 4]) {
  while (hlen >= 4 * BYTES(OPP_B)) {
    __m256i B[16];

    V4_ALPHA_UPDATE_1(L);
    V4_LOAD_BLOCK(B, h);
    V4_BLOCKCIPHER_F(B, L);
    V4_ACCUMULATE(T, B);
    V4_ALPHA_UPDATE_2(L);
    h += 4 * BYTES(OPP_B);
    hlen -= 4 * BYTES(OPP_B);
  }

  /* TODO: V2 */

  while (hlen >= BYTES(OPP_B)) {
    __m256i B[4];

    V1_LOAD_BLOCK(B, h);
    V1_BLOCKCIPHER_F(B, L);
    V1_ACCUMULATE(T, B);

    V1_ALPHA_UPDATE(L);
    h += BYTES(OPP_B);
    hlen -= BYTES(OPP_B);
  }

  if (hlen > 0) {
    uint8_t lastblock[BYTES(OPP_B)];
    __m256i B[4];
    V1_BETA_UPDATE(L);
    opp_pad(lastblock, h, hlen);
    V1_LOAD_BLOCK(B, lastblock);
    V1_BLOCKCIPHER_F(B, L);
    V1_ACCUMULATE(T, B);
  }
}

static void opp_encrypt_data(__m256i T[4],
                             uint8_t *c,
                             const uint8_t *m,
                             size_t mlen,
                             uint64_t L[16 + 4]) {
  while (mlen >= 4 * BYTES(OPP_B)) {
    __m256i B[16];
    V4_ALPHA_UPDATE_1(L);
    V4_LOAD_BLOCK(B, m);
    V4_ACCUMULATE(T, B);
    V4_BLOCKCIPHER_F(B, L);
    V4_STORE_BLOCK(c, B);
    V4_ALPHA_UPDATE_2(L);
    c += 4 * BYTES(OPP_B);
    m += 4 * BYTES(OPP_B);
    mlen -= 4 * BYTES(OPP_B);
  }

  /* TODO: V2 */

  while (mlen >= BYTES(OPP_B)) {
    __m256i B[4];

    V1_LOAD_BLOCK(B, m);
    V1_ACCUMULATE(T, B);
    V1_BLOCKCIPHER_F(B, L);
    V1_STORE_BLOCK(c, B);

    V1_ALPHA_UPDATE(L);
    c += BYTES(OPP_B);
    m += BYTES(OPP_B);
    mlen -= BYTES(OPP_B);
  }

  if (mlen > 0) { /* handle partial final block */
    uint8_t lastblock[BYTES(OPP_B)];
    __m256i B[4];
    int i;
    V1_BETA_UPDATE(L);
    opp_pad(lastblock, m, mlen);
    V1_ZERO_BLOCK(B);
    V1_BLOCKCIPHER_F(B, L);
    for (i = 0; i < 4; ++i) { /* lastblock xor B and T xor last block */
      const __m256i M_i = LOADU256(&lastblock[32 * i]);
      T[i] = XOR256(T[i], M_i);
      STOREU256(&lastblock[32 * i], XOR256(B[i], M_i));
    }
    memcpy(c, lastblock, mlen);
  }
}

static void opp_decrypt_data(__m256i T[4],
                             uint8_t *m,
                             const uint8_t *c,
                             size_t clen,
                             uint64_t L[16 + 4]) {
  while (clen >= 4 * BYTES(OPP_B)) {
    __m256i B[16];
    V4_ALPHA_UPDATE_1(L);
    V4_LOAD_BLOCK(B, c);
    V4_BLOCKCIPHER_B(B, L);
    V4_ACCUMULATE(T, B);
    V4_STORE_BLOCK(m, B);
    V4_ALPHA_UPDATE_2(L);
    m += 4 * BYTES(OPP_B);
    c += 4 * BYTES(OPP_B);
    clen -= 4 * BYTES(OPP_B);
  }

  /* TODO: V2 */

  while (clen >= BYTES(OPP_B)) {
    __m256i B[4];

    V1_LOAD_BLOCK(B, c);
    V1_BLOCKCIPHER_B(B, L);
    V1_ACCUMULATE(T, B);
    V1_STORE_BLOCK(m, B);

    V1_ALPHA_UPDATE(L);
    m += BYTES(OPP_B);
    c += BYTES(OPP_B);
    clen -= BYTES(OPP_B);
  }

  if (clen > 0) { /* handle partial final block */
    uint8_t lastblock[BYTES(OPP_B)];
    __m256i B[4];
    int i;
    V1_BETA_UPDATE(L);
    opp_pad(lastblock, c, clen);
    V1_ZERO_BLOCK(B);
    V1_BLOCKCIPHER_F(B, L);
    for (i = 0; i < 4; ++i) { /* lastblock xor B */
      const __m256i C_i = LOADU256(&lastblock[32 * i]);
      STOREU256(&lastblock[32 * i], XOR256(B[i], C_i));
    }
    memcpy(m, lastblock, clen);
    opp_pad(lastblock, m, clen);
    for (i = 0; i < 4; ++i) { /* T xor last block */
      T[i] = XOR256(T[i], LOADU256(&lastblock[32 * i]));
    }
  }
}

static void opp_tag(__m256i *Te, const __m256i *Ta, uint64_t *L) {
  size_t i;
  for (i = 0; i < 2; ++i) {
    V1_BETA_UPDATE(L);
  }
  // Remove block cipher call
  // V1_BLOCKCIPHER_F(Te, L);
  V1_ACCUMULATE(Te, Ta);
}

#if defined(OPP_DEBUG)
static void print_mask(uint64_t *L) {
  int i;
  for (i = 0; i < 16; ++i) {
    printf("%016lX%c", L[i], i % 4 == 3 ? '\n' : ' ');
  }
  printf("\n");
}

static void print_state(__m256i *B) {
  uint64_t L[16];
  int i;
  for (i = 0; i < 4; ++i) {
    STOREU256(&L[4 * i], B[i]);
  }
  print_mask(L);
}
#endif

/* high level interface functions */
static int crypto_aead_encrypt_and_tag(unsigned char *c,
                                       unsigned char *tag,
                                       const unsigned char *h,
                                       size_t hlen,
                                       const unsigned char *m,
                                       size_t mlen,
                                       const unsigned char *n,
                                       const unsigned char *k) {
  __m256i Ta[4] = {0};
  __m256i Te[4] = {0};
  uint64_t Ka[16 + 4];
  uint64_t Ke[16 + 4];

  opp_kdf(Ka, Ke, k, n);

#if defined(OPP_DEBUG)
  print_mask(Ka);
  print_mask(Ke);
#endif

  opp_hash_data(Ta, h, hlen, Ka);
  opp_encrypt_data(Te, c, m, mlen, Ke);
  opp_tag(Te, Ta, Ke);

#if defined(OPP_DEBUG)
  print_state(Te);
#endif

  STOREU256(tag, Te[0]);

#if defined(DEBUG)
  {
    int i;
    for (i = 0; i < *clen; ++i)
      printf("%02X ", c[i]);
    printf("\n");
  }
#endif
  return 1;
}

static int crypto_aead_partial_decrypt(unsigned char *tag,
                                       unsigned char *m,
                                       const unsigned char *h,
                                       size_t hlen,
                                       const unsigned char *c,
                                       size_t clen,
                                       const unsigned char *n,
                                       const unsigned char *k) {
  __m256i Ta[4] = {0};
  __m256i Te[4] = {0};
  uint64_t Ka[16 + 4];
  uint64_t Ke[16 + 4];

  if (clen < BYTES(OPP_T))
    return -1;
  // *mlen = clen - BYTES(OPP_T);

  opp_kdf(Ka, Ke, k, n);

  opp_hash_data(Ta, h, hlen, Ka);
  opp_decrypt_data(Te, m, c, clen - BYTES(OPP_T), Ke);
  opp_tag(Te, Ta, Ke);

  STOREU256(tag, Te[0]);
  return 1;
}

/* ------------------------------------------------------------------------- */
/* Aead interface for Blake2b-OPP-MEM                                        */

#include <assert.h>

#include <cryptography-run/aead.h>
#include <cryptography-run/axu.h>
#include <cryptography-run/hash.h>
#include "../../../internal.h"

static const uint8_t aead_och_blake2b_mem_key_len = 32;
static const uint8_t aead_och_blake2b_mem_nonce_len = 32;
static const uint8_t aead_och_blake2b_mem_overhead = 32;

static const uint8_t label_och_kg[1] = {0x42};
static const uint8_t label_och_tag[1] = {0x43};
static const uint8_t label_xth_kg[1] = {0x44};
static const uint8_t label_xth_tag[1] = {0x45};

/** permutation width = 128 bytes */
static const size_t och_n = BYTES(OPP_B);
/** permutation width = 32 bytes */
static const size_t inner_tag_len = BYTES(OPP_T);

typedef struct {
  alignas(32) uint8_t cr_prf_key[32];
  alignas(32) uint8_t core_tbc_key[32];
  alignas(32) PolyvalX2Key core_axu_key;
  alignas(32) uint8_t tiny_tbc_key[32];
  alignas(32) PolyvalX2Key tiny_axu_key;
  alignas(8) uint8_t blake2b_ctx[248];
} blake2b_opp_mem_ctx;

int aead_och_blake2b_mem_init(AeadKey *aead_key,
                              const uint8_t *key,
                              size_t key_len) {
  int ret = 1;
  blake2b_opp_mem_ctx *ctx = (blake2b_opp_mem_ctx *)aead_key;
  HashState *hash_ctx = (HashState *)ctx->blake2b_ctx;

  // the given key is the CR PRF key
  memcpy(ctx->cr_prf_key, key, aead_och_blake2b_mem_key_len);

  // Use the CR PRF to generate subkeys
  // Blake2b supports 64 byte outputs so we need two calls
  const size_t digest_len = 64;
  uint8_t digest[64] = {0};
  ret &= Hash_blake2b()->init(hash_ctx, key, key_len, digest_len);
  ret &= Hash_blake2b()->update(hash_ctx, label_xth_kg, 1);
  ret &= Hash_blake2b()->final(hash_ctx, digest, digest_len);
  memcpy(ctx->core_tbc_key, digest, 32);
  polyval_x2_setkey(&ctx->core_axu_key, digest + 32);
  ret &= Hash_blake2b()->init(hash_ctx, key, key_len, digest_len);
  ret &= Hash_blake2b()->update(hash_ctx, label_och_kg, 1);
  ret &= Hash_blake2b()->final(hash_ctx, digest, digest_len);
  memcpy(ctx->tiny_tbc_key, digest, 32);
  polyval_x2_setkey(&ctx->tiny_axu_key, digest + 32);

  return ret;
}

int aead_och_blake2b_mem_seal(AeadKey *aead_key,
                              uint8_t *ct,
                              const uint8_t *msg,
                              size_t msg_len,
                              const uint8_t *ad,
                              size_t ad_len,
                              const uint8_t *nonce) {
  int ret = 1;
  blake2b_opp_mem_ctx *ctx = (blake2b_opp_mem_ctx *)aead_key;

  uint8_t *tag = ct + msg_len;
  uint8_t inner_tag[32] = {0};

  if (msg_len >= och_n) {
    ret &= crypto_aead_encrypt_and_tag(ct, inner_tag, NULL, 0, msg, msg_len,
                                       nonce, ctx->core_tbc_key);
    // FIXME: implement handling for partial blocks
    polyval_x2_key_oneshot(&ctx->tiny_axu_key, inner_tag, 2, inner_tag);
    ret &= xth_hash(Hash_blake2b(), tag, ctx->cr_prf_key,
                    aead_och_blake2b_mem_key_len, nonce,
                    aead_och_blake2b_mem_nonce_len, ad, ad_len, inner_tag,
                    inner_tag_len);
  } else {
    if ((msg_len % POLYVAL_BLOCK_SIZE) != 0) {
      return 0;
    }
    size_t nblocks = msg_len / POLYVAL_BLOCK_SIZE;
    polyval_x2_key_oneshot(&ctx->tiny_axu_key, msg, nblocks, inner_tag);

    ret &= xth_hash(Hash_blake2b(), tag, ctx->cr_prf_key,
                    aead_och_blake2b_mem_key_len, nonce,
                    aead_och_blake2b_mem_nonce_len, ad, ad_len, inner_tag,
                    inner_tag_len);

    // Use nonce to generate TBC key
    uint64_t Ka[16 + 4];
    uint64_t Ke[16 + 4];
    opp_kdf(Ka, Ke, ctx->tiny_tbc_key, nonce);

    __m256i state[4] = {0};
    V1_ZERO_BLOCK(state);
    state[0] = LOADU256(tag);
    V1_BLOCKCIPHER_F(state, Ke);
    if (msg_len == 16) {
      STOREU128(ct, XOR128(_mm256_castsi256_si128(state[0]), LOADU128(msg)));
    } else if (msg_len == 32) {
      STOREU256(ct, XOR256(state[0], LOADU256(msg)));
    } else if (msg_len == 64) {
      STOREU256(ct, XOR256(state[0], LOADU256(msg)));
      STOREU256(ct + 32, XOR256(state[1], LOADU256(msg + 32)));
    }
  }

  return ret;
}

int aead_och_blake2b_mem_open(AeadKey *aead_key,
                              uint8_t *msg,
                              const uint8_t *ct,
                              size_t ct_len,
                              const uint8_t *ad,
                              size_t ad_len,
                              const uint8_t *nonce) {
  int ret = 1;
  blake2b_opp_mem_ctx *ctx = (blake2b_opp_mem_ctx *)aead_key;

  size_t ct_core_len = ct_len - aead_och_blake2b_mem_overhead;
  size_t msg_len = ct_core_len;

  uint8_t inner_tag[32] = {0};
  const uint8_t given_tag = ct + ct_core_len;
  uint8_t expected_tag[32] = {0};

  if (ct_core_len >= och_n) {
    ret &= crypto_aead_partial_decrypt(inner_tag, msg, NULL, 0, ct, ct_len,
                                       nonce, ctx->core_tbc_key);
    // FIXME: implement handling for partial blocks
    polyval_x2_key_oneshot(&ctx->tiny_axu_key, inner_tag, 2, inner_tag);
    ret &= xth_hash(Hash_blake2b(), expected_tag, ctx->cr_prf_key,
                    aead_och_blake2b_mem_key_len, nonce,
                    aead_och_blake2b_mem_nonce_len, ad, ad_len, inner_tag,
                    inner_tag_len);
  } else {
    // Use nonce to generate TBC key
    uint64_t Ka[16 + 4];
    uint64_t Ke[16 + 4];
    opp_kdf(Ka, Ke, ctx->tiny_tbc_key, nonce);

    // FIXME: turn this into a proper function
    __m256i state[4] = {0};
    V1_ZERO_BLOCK(state);
    state[0] = LOADU256(given_tag);
    V1_BLOCKCIPHER_F(state, Ke);
    if (msg_len == 16) {
      STOREU128(msg, XOR128(_mm256_castsi256_si128(state[0]), LOADU128(ct)));
    } else if (msg_len == 32) {
      STOREU256(msg, XOR256(state[0], LOADU256(ct)));
    } else if (msg_len == 64) {
      STOREU256(msg, XOR256(state[0], LOADU256(ct)));
      STOREU256(msg + 32, XOR256(state[1], LOADU256(ct + 32)));
    }

    if ((msg_len % POLYVAL_BLOCK_SIZE) != 0) {
      return 0;
    }
    size_t nblocks = msg_len / POLYVAL_BLOCK_SIZE;
    polyval_x2_key_oneshot(&ctx->tiny_axu_key, msg, nblocks, inner_tag);

    ret &= xth_hash(Hash_blake2b(), expected_tag, ctx->cr_prf_key,
                    aead_och_blake2b_mem_key_len, nonce,
                    aead_och_blake2b_mem_nonce_len, ad, ad_len, inner_tag,
                    inner_tag_len);
  }

  ret &= constant_time_compare(expected_tag, given_tag,
                               aead_och_blake2b_mem_overhead);

  return ret;
}

static const Aead aead_och_blake2b_mem = {"OCH-Blake2b-MEM",
                                          aead_och_blake2b_mem_key_len,
                                          aead_och_blake2b_mem_nonce_len,
                                          aead_och_blake2b_mem_overhead,
                                          aead_och_blake2b_mem_init,
                                          aead_och_blake2b_mem_seal,
                                          aead_och_blake2b_mem_open,
                                          NULL,
                                          NULL};

const Aead *Aead_och_blake2b_mem() {
  return &aead_och_blake2b_mem;
}

int aead_och_blake2b_sha256_mem_seal(AeadKey *aead_key,
                                     uint8_t *ct,
                                     const uint8_t *msg,
                                     size_t msg_len,
                                     const uint8_t *ad,
                                     size_t ad_len,
                                     const uint8_t *nonce) {
  int ret = 1;
  blake2b_opp_mem_ctx *ctx = (blake2b_opp_mem_ctx *)aead_key;

  uint8_t *tag = ct + msg_len;
  uint8_t inner_tag[32] = {0};

  if (msg_len >= och_n) {
    ret &= crypto_aead_encrypt_and_tag(ct, inner_tag, NULL, 0, msg, msg_len,
                                       nonce, ctx->core_tbc_key);
    // FIXME: implement handling for partial blocks
    polyval_x2_key_oneshot(&ctx->tiny_axu_key, inner_tag, 2, inner_tag);
    ret &= xth_hash(Hash_sha256(), tag, ctx->cr_prf_key,
                    aead_och_blake2b_mem_key_len, nonce,
                    aead_och_blake2b_mem_nonce_len, ad, ad_len, inner_tag,
                    inner_tag_len);
  } else {
    if ((msg_len % POLYVAL_BLOCK_SIZE) != 0) {
      return 0;
    }
    size_t nblocks = msg_len / POLYVAL_BLOCK_SIZE;
    polyval_x2_key_oneshot(&ctx->tiny_axu_key, msg, nblocks, inner_tag);

    ret &= xth_hash(Hash_sha256(), tag, ctx->cr_prf_key,
                    aead_och_blake2b_mem_key_len, nonce,
                    aead_och_blake2b_mem_nonce_len, ad, ad_len, inner_tag,
                    inner_tag_len);

    // Use nonce to generate TBC key
    uint64_t Ka[16 + 4];
    uint64_t Ke[16 + 4];
    opp_kdf(Ka, Ke, ctx->tiny_tbc_key, nonce);

    __m256i state[4] = {0};
    V1_ZERO_BLOCK(state);
    state[0] = LOADU256(tag);
    V1_BLOCKCIPHER_F(state, Ke);
    if (msg_len == 16) {
      STOREU128(ct, XOR128(_mm256_castsi256_si128(state[0]), LOADU128(msg)));
    } else if (msg_len == 32) {
      STOREU256(ct, XOR256(state[0], LOADU256(msg)));
    } else if (msg_len == 64) {
      STOREU256(ct, XOR256(state[0], LOADU256(msg)));
      STOREU256(ct + 32, XOR256(state[1], LOADU256(msg + 32)));
    }
  }

  return ret;
}

int aead_och_blake2b_sha256_mem_open(AeadKey *aead_key,
                                     uint8_t *msg,
                                     const uint8_t *ct,
                                     size_t ct_len,
                                     const uint8_t *ad,
                                     size_t ad_len,
                                     const uint8_t *nonce) {
  int ret = 1;
  blake2b_opp_mem_ctx *ctx = (blake2b_opp_mem_ctx *)aead_key;

  size_t ct_core_len = ct_len - aead_och_blake2b_mem_overhead;
  size_t msg_len = ct_core_len;

  uint8_t inner_tag[32] = {0};
  const uint8_t given_tag = ct + ct_core_len;
  uint8_t expected_tag[32] = {0};

  if (ct_core_len >= och_n) {
    ret &= crypto_aead_partial_decrypt(inner_tag, msg, NULL, 0, ct, ct_len,
                                       nonce, ctx->core_tbc_key);
    // FIXME: implement handling for partial blocks
    polyval_x2_key_oneshot(&ctx->tiny_axu_key, inner_tag, 2, inner_tag);
    ret &= xth_hash(Hash_sha256(), expected_tag, ctx->cr_prf_key,
                    aead_och_blake2b_mem_key_len, nonce,
                    aead_och_blake2b_mem_nonce_len, ad, ad_len, inner_tag,
                    inner_tag_len);
  } else {
    // Use nonce to generate TBC key
    uint64_t Ka[16 + 4];
    uint64_t Ke[16 + 4];
    opp_kdf(Ka, Ke, ctx->tiny_tbc_key, nonce);

    // FIXME: turn this into a proper function
    __m256i state[4] = {0};
    V1_ZERO_BLOCK(state);
    state[0] = LOADU256(given_tag);
    V1_BLOCKCIPHER_F(state, Ke);
    if (msg_len == 16) {
      STOREU128(msg, XOR128(_mm256_castsi256_si128(state[0]), LOADU128(ct)));
    } else if (msg_len == 32) {
      STOREU256(msg, XOR256(state[0], LOADU256(ct)));
    } else if (msg_len == 64) {
      STOREU256(msg, XOR256(state[0], LOADU256(ct)));
      STOREU256(msg + 32, XOR256(state[1], LOADU256(ct + 32)));
    }

    if ((msg_len % POLYVAL_BLOCK_SIZE) != 0) {
      return 0;
    }
    size_t nblocks = msg_len / POLYVAL_BLOCK_SIZE;
    polyval_x2_key_oneshot(&ctx->tiny_axu_key, msg, nblocks, inner_tag);

    ret &= xth_hash(Hash_sha256(), expected_tag, ctx->cr_prf_key,
                    aead_och_blake2b_mem_key_len, nonce,
                    aead_och_blake2b_mem_nonce_len, ad, ad_len, inner_tag,
                    inner_tag_len);
  }

  ret &= constant_time_compare(expected_tag, given_tag,
                               aead_och_blake2b_mem_overhead);

  return ret;
}

static const Aead aead_och_blake2b_sha256_mem = {
    "OCH-Blake2b-SHA256-MEM",
    aead_och_blake2b_mem_key_len,
    aead_och_blake2b_mem_nonce_len,
    aead_och_blake2b_mem_overhead,
    aead_och_blake2b_mem_init,
    aead_och_blake2b_sha256_mem_seal,
    aead_och_blake2b_sha256_mem_open,
    NULL,
    NULL};

const Aead *Aead_och_blake2b_sha256_mem() {
  return &aead_och_blake2b_sha256_mem;
}