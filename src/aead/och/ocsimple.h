/*
    OCSimple[Perm1, Perm2]

    :copyright: (c) 2025 by OCH authors.
    :license: Creative Commons CC0 1.0
*/

#ifndef CR_OCSIMPLE_H
#define CR_OCSIMPLE_H

#include <cryptography-run/aead.h>
#include <cryptography-run/axuhash.h>
#include <cryptography-run/hash.h>

#include "em256.h"
#include "od512.h"

#if defined(__cplusplus)
extern "C" {
#endif

// Number of entries in the offset table to precompute
#define L_SIZE 16

static const uint8_t ocsimple_key_len = 32;

static const uint8_t ocsimple_perm1_width = 32;
static const uint8_t ocsimple_perm2_width = 64;

static const uint8_t ocsimple_tag_len = 32;

static const uint8_t ocsimple_s_pubnonce_len = 0;
static const uint8_t ocsimple_s_secnonce_len = 32;
static const uint8_t ocsimple_s_overhead =
    ocsimple_s_secnonce_len + ocsimple_tag_len;

static const uint8_t ocsimple_p_pubnonce_len = 32;
static const uint8_t ocsimple_p_secnonce_len = 0;
static const uint8_t ocsimple_p_overhead =
    ocsimple_p_secnonce_len + ocsimple_tag_len;

static const uint8_t label_ocsimple_tiny = 0xf1;
static const uint8_t label_ocsimple_core_no_partial = 0xf2;
static const uint8_t label_ocsimple_core_with_partial = 0xf3;

typedef u128_t Checksum;
// TODO: use this for extended checksum
typedef u256_t ExtendedChecksum;

typedef struct {
  /** perm1 as EM */
  const EM256 *em;
  /** perm2 as duplex_chunk */
  OD512_DuplexChunk duplex_chunk;

  /** configuration */
  uint8_t pubnonce_len;
  uint8_t secnonce_len;

  /** capacity of OD[perm2] */
  OD512Cap cap;
  /** Offset L_* */
  EMOffset LStar;
  /** Offset table L */
  EMOffset L[L_SIZE];

  /** cached Top = secnonce[:-6] */
  u256_t cached_Top;
  /** cached (KTop, cap) = OD.Duplexing(Top, cap) */
  EMOffset cached_KTop;
  OD512Cap cached_cap;
} OCSimple256_512_key;

static int OCSimple256_512_init(const EM256 *em,
                                OD512_DuplexChunk duplex_chunk,
                                const uint8_t pubnonce_len,
                                const uint8_t secnonce_len,
                                AeadKey *aead_key,
                                const uint8_t *key,
                                size_t key_len) {
  int ret = 1;
  OCSimple256_512_key *new_key = (OCSimple256_512_key *)aead_key;

  new_key->em = em;
  new_key->duplex_chunk = duplex_chunk;

  new_key->pubnonce_len = pubnonce_len;
  new_key->secnonce_len = secnonce_len;

  new_key->cap = zero256();

  assert(key_len == 32);
  ret &= OD512_Duplexing(new_key->duplex_chunk, &new_key->cap, &new_key->LStar,
                         key, key_len);
  new_key->L[0] = gf256_double(new_key->LStar);
  for (int i = 1; i < L_SIZE; i++) {
    new_key->L[i] = gf256_double(new_key->L[i - 1]);
  }

  /** initialize the cache */
  new_key->cached_Top = zero256();
  new_key->cached_KTop = zero256();
  new_key->cached_cap = zero256();

  return ret;
}

static int OCSimple256_512_S_init(const EM256 *em,
                                  OD512_DuplexChunk duplex_chunk,
                                  AeadKey *aead_key,
                                  const uint8_t *key,
                                  size_t key_len) {
  uint8_t pubnonce_len = ocsimple_s_pubnonce_len;
  uint8_t secnonce_len = ocsimple_s_secnonce_len;

  return OCSimple256_512_init(em, duplex_chunk, pubnonce_len, secnonce_len,
                              aead_key, key, key_len);
}

static int OCSimple256_512_P_init(const EM256 *em,
                                  OD512_DuplexChunk duplex_chunk,
                                  AeadKey *aead_key,
                                  const uint8_t *key,
                                  size_t key_len) {
  uint8_t pubnonce_len = ocsimple_p_pubnonce_len;
  uint8_t secnonce_len = ocsimple_p_secnonce_len;

  return OCSimple256_512_init(em, duplex_chunk, pubnonce_len, secnonce_len,
                              aead_key, key, key_len);
}

static bool OCSimple256_512_validate_key(OCSimple256_512_key *key) {
  if (!((key->pubnonce_len + key->secnonce_len) <= ocsimple_perm1_width)) {
    return false;
  }
  if ((key->secnonce_len > 0) && !(key->pubnonce_len < ocsimple_perm1_width)) {
    return false;
  }
  return true;
}

/** Returns a byte B with
 * B[0:1] = 0 if has_partial=false
 *        = 1 if has_partial=true
 * B[1:2] = 0 if secnonce_len = 0
 *        = 1 if secnonce_len > 0
 * B[2:8] = zeros if secnonce_len = 0
 *        = Bottom(secnonce) if secnonce_len > 0
 */
static inline uint8_t encode_secnonce_Bottom(uint8_t secnonce_len,
                                             const uint8_t *secnonce,
                                             bool has_partial) {
  uint8_t out = 0;
  assert((secnonce_len == 0) || (secnonce_len == 16) || (secnonce_len == 32));
  if (secnonce_len > 0) {
    out = secnonce[secnonce_len - 1] & 0b00111111;
    out = out | 0b01000000;
  }
  if (has_partial) {
    out = out | 0b10000000;
  }
  return out;
}

/**
 * Compute the inital offset Delta_NP_NS_0, and update |cap|.
 * If outdated, update key->cached_Top, key->cached_cap, and key->cached_KTop.
 * @return true on success and false otherwise.
 */
static int OCSimple256_512_init_offset(OCSimple256_512_key *key,
                                       OD512Cap *cap,
                                       EMOffset *Delta_NP_NS_0,
                                       const uint8_t *pubnonce,
                                       const uint8_t *secnonce) {
  // TODO: implement other choices
  assert((key->secnonce_len == 32) && (key->pubnonce_len == 0));

  // split the secnonce into Top and Bottom
  uint8_t Bottom = secnonce[31] & 0b00111111;
  u256_t Top = load256(secnonce);
  Top.u8[31] = Top.u8[31] & 0b11000000;

  u256_t KTop = zero256();
  // check cache
  if (equal256(key->cached_Top, Top)) {
    KTop = copy256(key->cached_KTop);
    *cap = copy256(key->cached_cap);
  } else {
    // compute KTop
    KTop = copy256(Top);
    key->duplex_chunk(&KTop, cap);
    // update cache
    key->cached_Top = copy256(Top);
    key->cached_KTop = copy256(KTop);
    key->cached_cap = copy256(*cap);
  }
  // compute initial offset
  *Delta_NP_NS_0 = copy256(shiftleft256(KTop, Bottom));
  return 1;
}

/**
 * Compute OCSimple tag with no partial block
 * @return 1 on success
 */
static int OCHSimple_OD512_tag_tiny(const OCSimple256_512_key *key,
                                    OD512Cap *cap,
                                    uint8_t *out_tag,
                                    const uint8_t *ad,
                                    size_t ad_len,
                                    const uint8_t *msg,
                                    size_t msg_len,
                                    const uint8_t *secnonce) {
  u256_t digest = zero256();
  // hash ad
  OD512_Duplexing(key->duplex_chunk, cap, &digest, ad, ad_len);
  // hash secnonce
  digest = zero256();
  OD512_Duplexing(key->duplex_chunk, cap, &digest, secnonce, key->secnonce_len);

  assert((key->secnonce_len == 0) || (key->secnonce_len == 32));
  if (key->secnonce_len == 32) {
    // [  0:256] = secnonce
    digest = load256(secnonce);
    key->duplex_chunk(&digest, cap);
  }

  // hash msg
  OD512_Duplexing(key->duplex_chunk, cap, &digest, ad, ad_len);

  digest = zero256();
  assert(msg_len < 32);
  for (size_t j = 0; j < msg_len; j++) {
    digest.u8[j] = msg[j];
  }
  digest.u8[msg_len] = label_ocsimple_tiny;
  key->duplex_chunk(&digest, cap);
  store256(out_tag, digest);
  return 1;
}

/**
 * Compute OCSimple tag with no partial block
 * @return 1 on success
 */
static int OCHSimple_OD512_tag_no_partial(const OCSimple256_512_key *key,
                                          OD512Cap *cap,
                                          uint8_t *out_tag,
                                          const uint8_t *ad,
                                          size_t ad_len,
                                          const Checksum Checksum,
                                          const uint64_t m,
                                          const uint8_t *secnonce) {
  bool has_partial = false;
  u256_t digest = zero256();
  OD512_Duplexing(key->duplex_chunk, cap, &digest, ad, ad_len);

  // zero-out |digest| and construct a new 256-bit input block to duplex
  // [  0:128] = checksum
  // [128:184] = zeros
  // [184:192] = Bottom(secnonce) + has_partial
  // [192:256] = m (number of full blocks encrypted)
  digest = zero256();
  digest.u128[0] = Checksum;
  digest.u8[23] =
      encode_secnonce_Bottom(key->secnonce_len, secnonce, has_partial);
  digest.u64[3] = m;

  key->duplex_chunk(&digest, cap);
  store256(out_tag, digest);
  return 1;
}

/**
 * Compute OCSimple tag with a partial block
 *
 * This is optimal if |ad| is block-aligned. In the worst-case, if |ad_len| = 33
 * for example, then it does an extra compression function call.
 *
 * @return 1 on success
 */
static int OCHSimple_OD512_tag_with_partial(const OCSimple256_512_key *key,
                                            OD512Cap *cap,
                                            uint8_t *out_tag,
                                            const uint8_t *ad,
                                            size_t ad_len,
                                            ExtendedChecksum ExChk,
                                            size_t ExChk_len,
                                            const uint64_t m,
                                            const uint8_t *secnonce) {
  bool has_partial = true;
  u256_t digest = zero256();
  OD512_Duplexing(key->duplex_chunk, cap, &digest, ad, ad_len);

  if (ExChk_len <= 23) {
    // if ExChk is small enough, we encode it all into one 256-bit block
    // [  0:184] = extended_checksum
    // [184:192] = Bottom(secnonce) + has_partial
    // [192:256] = m (number of full blocks encrypted)
    digest = zero256();
    digest = ExChk;
    digest.u8[23] =
        encode_secnonce_Bottom(key->secnonce_len, secnonce, has_partial);
    digest.u64[3] = m;

    key->duplex_chunk(&digest, cap);
    store256(out_tag, digest);
    return 1;
  }
  // else we need two compression function calls
  // first, for the extended checksum
  // [  0:256] = extended_checksum
  digest = zero256();
  digest = ExChk;
  key->duplex_chunk(&digest, cap);

  // second for the other data
  // [  0:184] = zeros
  // [184:192] = Bottom(secnonce) + has_partial
  // [192:256] = m (number of full blocks encrypted)
  digest = zero256();
  digest.u8[23] =
      encode_secnonce_Bottom(key->secnonce_len, secnonce, has_partial);
  digest.u64[3] = m;

  key->duplex_chunk(&digest, cap);
  store256(out_tag, digest);
  return 1;
}

#ifdef __cplusplus
}
#endif

#endif  // CR_OCSIMPLE_H
