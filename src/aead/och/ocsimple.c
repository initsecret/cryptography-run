/*
    OCSimple

    :copyright: (c) 2025 by OCH authors.
    :license: Creative Commons CC0 1.0
*/

#include "ocsimple.h"

static int OCSimple256_512_seal(AeadKey *aead_key,
                                uint8_t *ct,
                                const uint8_t *msg,
                                size_t msg_len,
                                const uint8_t *ad,
                                size_t ad_len,
                                const uint8_t *pubnonce,
                                const uint8_t *secnonce) {
  int ret = 1;
  OCSimple256_512_key *key = (OCSimple256_512_key *)aead_key;
  if (!OCSimple256_512_validate_key(key)) {
    return 0;
  }

  // Compute lengths
  size_t tag_len = ocsimple_tag_len;
  assert(tag_len == 32);
  size_t ctcore_len = key->secnonce_len + msg_len;
  uint8_t *out_tag = ct + ctcore_len;

  // Make a copy of cap
  OD512Cap cap = copy256(key->cap);

  EMOffset Delta_NP = zero256();
  EMOffset Delta_NP_NS_0 = zero256();
  Checksum Chk = zero128();

  OD512_Duplexing(key->duplex_chunk, &cap, &Delta_NP, pubnonce,
                  key->pubnonce_len);

  // OCSimple-Tiny
  if ((key->secnonce_len + msg_len) < ocsimple_perm1_width) {
    // TODO: Return u256_t to avoid store below
    ret &= OCHSimple_OD512_tag_tiny(key, &cap, out_tag, ad, ad_len, msg,
                                    msg_len, secnonce);
    EMOffset Delta_NP_star = xor256(Delta_NP, key->LStar);
    block Pad = load256(out_tag);
    key->em->EM_encrypt(Delta_NP_star, &Pad);
    for (int j = 0; j < key->secnonce_len; j += 1) {
      ct[j] = Pad.u8[j] ^ secnonce[j];
    }
    for (int j = 0; j < msg_len; j += 1) {
      ct[key->secnonce_len + j] = Pad.u8[key->secnonce_len + j] ^ msg[j];
    }
    return ret;
  }

  // NOTE: The caller may reuse buffers, ct = msg, so we always need to read
  //       |secnonce_len| bytes ahead to avoid corrupting buffers. This is not a
  //       problem in OCB because it does not do nonce hiding.

  /** offset in the msg buffer, updated on load */
  int msg_idx = 0;
  /** offset in the ct buffer, updated on store */
  int ct_idx = 0;

  /** i in pseudocode */
  uint64_t i = 0;

  bool read_ahead = true ? (key->secnonce_len > 0) : false;

  /** corresponds to P1 and C1 in pseudocode */
  block Bufi = zero256();

  if (key->secnonce_len == 0) {
    // if no secnonce, then skip this part, except updating offsets
    Delta_NP_NS_0 = Delta_NP;
  } else if ((key->secnonce_len == 32) && (key->pubnonce_len == 0)) {
    // if the secnonce is a block, then encrypt that block with Delta_NP
    // we will store it after reading the next block
    assert(read_ahead);
    Bufi = load256(secnonce);
    Chk = xor128(Chk, Bufi.u128[0]);
    key->em->EM_encrypt(Delta_NP, &Bufi);
    i += 1;

    // generate offset based on pubnonce and secnonce
    ret &= OCSimple256_512_init_offset(key, &cap, &Delta_NP_NS_0, pubnonce,
                                       secnonce);
  } else {
    assert(false);  // unimplemented
    return 0;
  }

  /** corresponds to Delta_NP_NS_i */
  EMOffset Delta_NP_NS_i = Delta_NP_NS_0;
  assert((i == 0) || (i == 1));
  if (i == 1) {
    Delta_NP_NS_i = xor256(Delta_NP_NS_i, key->L[ntz(1)]);
  }

  // Try encrypting blocks in groups of four
  if (msg_len > 4 * 32) {
    block Bufi4[4] = {zero256(), zero256(), zero256(), Bufi};
    EMOffset Off4[4] = {zero256(), zero256(), zero256(), Delta_NP_NS_i};
    for (; (msg_idx + (4 * 32)) <= msg_len; msg_idx += (4 * 32)) {
      assert(ct_idx <= msg_idx);

      if (read_ahead) {
        Bufi4[0] = load256(msg + msg_idx);
        store256(ct + ct_idx, Bufi4[3]);
        ct_idx += 32;
      } else {
        Bufi4[0] = load256(msg + msg_idx);
      }

      Bufi4[1] = load256(msg + msg_idx + 32);
      Bufi4[2] = load256(msg + msg_idx + (2 * 32));
      Bufi4[3] = load256(msg + msg_idx + (3 * 32));

      Chk = xor128(Chk, Bufi4[0].u128[0]);
      Chk = xor128(Chk, Bufi4[1].u128[0]);
      Chk = xor128(Chk, Bufi4[2].u128[0]);
      Chk = xor128(Chk, Bufi4[3].u128[0]);

      Off4[0] = xor256(Off4[3], key->L[ntz(i)]);
      Off4[1] = xor256(Off4[0], key->L[ntz(i + 1)]);
      Off4[2] = xor256(Off4[1], key->L[ntz(i + 2)]);
      Off4[3] = xor256(Off4[2], key->L[ntz(i + 3)]);

      key->em->EM_encrypt_x4(Off4, Bufi4);

      store256(ct + ct_idx, Bufi4[0]);
      store256(ct + ct_idx + 32, Bufi4[1]);
      store256(ct + ct_idx + (2 * 32), Bufi4[2]);
      ct_idx += (3 * 32);
      if (!read_ahead) {
        store256(ct + ct_idx, Bufi4[3]);
        ct_idx += 32;
      }

      i += 4;
    }
    Bufi = Bufi4[3];
    Delta_NP_NS_i = Off4[3];
  }

  // Encrypt remaining blocks one-by-one
  for (; (msg_idx + 32) <= msg_len; msg_idx += 32) {
    assert(ct_idx <= msg_idx);
    if (read_ahead) {
      block BufNext = load256(msg + msg_idx);
      store256(ct + ct_idx, Bufi);
      ct_idx += 32;
      Bufi = BufNext;
    } else {
      Bufi = load256(msg + msg_idx);
    }
    Chk = xor128(Chk, Bufi.u128[0]);
    Delta_NP_NS_i = xor256(Delta_NP_NS_i, key->L[ntz(i)]);
    key->em->EM_encrypt(Delta_NP_NS_i, &Bufi);

    if (!read_ahead) {
      store256(ct + ct_idx, Bufi);
      ct_idx += 32;
    }
    i += 1;
  }

  /** m in pseudocode = number of full blocks encrypted */
  uint64_t m = i;

  // If no partial block
  if (msg_idx == msg_len) {
    if (read_ahead) {
      store256(ct + ct_idx, Bufi);
      ct_idx += 32;
    }
    ret &= OCHSimple_OD512_tag_no_partial(key, &cap, out_tag, ad, ad_len, Chk,
                                          m, secnonce);
    return ret;
  }

  // Handle partial block
  uint8_t BufStar[32] = {0};  // corresponds to P_* and C_* in pseudocode
  size_t BufStar_len = msg_len - msg_idx;
  assert(BufStar_len < 32);
  ExtendedChecksum ExChk = zero256();
  ExChk.u128[0] = Chk;
  size_t ExChk_len = BufStar_len ? (BufStar_len > 16) : 16;
  // load any partial block before storing last full block
  assert(msg_idx + BufStar_len == msg_len);
  for (int i = 0; i < BufStar_len; i += 1) {
    BufStar[i] = msg[msg_idx + i];
    ExChk.u8[i] ^= BufStar[i];
  }
  // store last full block
  if (read_ahead) {
    store256(ct + ct_idx, Bufi);
    ct_idx += 32;
  }
  // encrypt partial block using Pad
  EMOffset Delta_NP_NS_m_star = xor256(Delta_NP_NS_i, key->LStar);
  block Pad = zero256();
  key->em->EM_encrypt(Delta_NP_NS_m_star, &Pad);
  assert(ct_idx + BufStar_len == ctcore_len);
  for (int j = 0; j < BufStar_len; j += 1) {
    ct[ct_idx + j] = Pad.u8[j] ^ BufStar[j];
  }

  ret &= OCHSimple_OD512_tag_with_partial(key, &cap, out_tag, ad, ad_len, ExChk,
                                          ExChk_len, m, secnonce);

  return ret;
}

static int OCSimple256_512_open(AeadKey *aead_key,
                                uint8_t *msg,
                                uint8_t *secnonce,
                                const uint8_t *ct,
                                size_t ct_len,
                                const uint8_t *ad,
                                size_t ad_len,
                                const uint8_t *pubnonce) {
  int ret = 1;
  OCSimple256_512_key *key = (OCSimple256_512_key *)aead_key;
  if (!OCSimple256_512_validate_key(key)) {
    return 0;
  }

  // Compute lengths
  size_t tag_len = ocsimple_tag_len;
  assert(tag_len == 32);
  assert(ct_len >= (tag_len + key->secnonce_len));
  size_t ctcore_len = ct_len - tag_len;
  size_t msg_len = ctcore_len - key->secnonce_len;
  const uint8_t *given_tag = ct + ctcore_len;

  // Make a copy of cap
  OD512Cap cap = copy256(key->cap);

  EMOffset Delta_NP = zero256();
  EMOffset Delta_NP_NS_0 = zero256();
  Checksum Chk = zero128();

  OD512_Duplexing(key->duplex_chunk, &cap, &Delta_NP, pubnonce,
                  key->pubnonce_len);

  // OCSimple-Tiny
  if ((key->secnonce_len + msg_len) < ocsimple_perm1_width) {
    EMOffset Delta_NP_star = xor256(Delta_NP, key->LStar);
    block Pad = load256(given_tag);
    key->em->EM_encrypt(Delta_NP_star, &Pad);
    for (int j = 0; j < key->secnonce_len; j += 1) {
      secnonce[j] = Pad.u8[j] ^ ct[j];
    }
    for (int j = 0; j < msg_len; j += 1) {
      msg[j] = Pad.u8[key->secnonce_len + j] ^ ct[key->secnonce_len + j];
    }

    /** corresponds to T_d^* = expected outer tag */
    uint8_t expected_tag[32] = {0};
    // TODO: Return u256_t to avoid store below
    ret &= OCHSimple_OD512_tag_tiny(key, &cap, expected_tag, ad, ad_len, msg,
                                    msg_len, secnonce);
    ret &= constant_time_compare(expected_tag, given_tag, tag_len);
    return ret;
  }

  int msg_idx = 0;  // offset in the msg buffer, updated on store

  int i = 0;  // i in pseudocode

  // correspond to P1 and C1 in pseudocode
  block Bufi = zero256();

  if (key->secnonce_len == 0) {
    // if no secnonce, then skip this part, except updating offsets
    Delta_NP_NS_0 = Delta_NP;
  } else if ((key->secnonce_len == 32) && (key->pubnonce_len == 0)) {
    // if the secnonce is a block, then decrypt the first block with Delta_NP
    assert(ct_len >= 32);
    Bufi = load256(ct);
    key->em->EM_decrypt(Delta_NP, &Bufi);
    Chk = xor128(Chk, Bufi.u128[0]);
    store256(secnonce, Bufi);
    i += 1;

    // generate offset based on pubnonce and secnonce
    ret &= OCSimple256_512_init_offset(key, &cap, &Delta_NP_NS_0, pubnonce,
                                       secnonce);
  } else {
    assert(false);  // unimplemented
    return 0;
  }

  /** corresponds to Delta_NP_NS_i */
  EMOffset Delta_NP_NS_i = Delta_NP_NS_0;
  assert((i == 1) || (i == 0));
  if (i == 1) {
    Delta_NP_NS_i = xor256(Delta_NP_NS_i, key->L[ntz(1)]);
  }

  // Decrypt remaining blocks one-by-one
  for (; (msg_idx + 32) <= msg_len; msg_idx += 32) {
    Bufi = load256(ct + key->secnonce_len + msg_idx);
    Delta_NP_NS_i = xor256(Delta_NP_NS_i, key->L[ntz(i)]);
    key->em->EM_decrypt(Delta_NP_NS_i, &Bufi);
    Chk = xor128(Chk, Bufi.u128[0]);

    store256(msg + msg_idx, Bufi);
    i += 1;
  }

  /** m in pseudocode = number of full blocks encrypted */
  uint64_t m = i;

  // If no partial block
  if (msg_idx == msg_len) {
    /** corresponds to T_d^* = expected outer tag */
    uint8_t expected_tag[32] = {0};
    ret &= OCHSimple_OD512_tag_no_partial(key, &cap, expected_tag, ad, ad_len,
                                          Chk, m, secnonce);
    ret &= constant_time_compare(expected_tag, given_tag, tag_len);
    return ret;
  }

  // Handle partial block
  uint8_t BufStar[32] = {0};  // corresponds to P_* and C_* in pseudocode
  size_t BufStar_len = msg_len - msg_idx;
  assert(BufStar_len < 32);
  ExtendedChecksum ExChk = zero256();
  ExChk.u128[0] = Chk;
  size_t ExChk_len = BufStar_len ? (BufStar_len > 16) : 16;

  // decrypt partial block using Pad
  EMOffset Delta_NP_NS_m_star = xor256(Delta_NP_NS_i, key->LStar);
  block Pad = zero256();
  key->em->EM_encrypt(Delta_NP_NS_m_star, &Pad);
  assert(msg_idx + BufStar_len == msg_len);
  for (int i = 0; i < BufStar_len; i += 1) {
    BufStar[i] = ct[key->secnonce_len + msg_idx + i];
    BufStar[i] = Pad.u8[i] ^ BufStar[i];
    msg[msg_idx + i] = BufStar[i];
    ExChk.u8[i] ^= BufStar[i];
  }

  /** corresponds to T_d^* = expected outer tag */
  uint8_t expected_tag[32] = {0};
  ret &= OCHSimple_OD512_tag_with_partial(key, &cap, expected_tag, ad, ad_len,
                                          ExChk, ExChk_len, m, secnonce);
  ret &= constant_time_compare(expected_tag, given_tag, tag_len);
  return ret;
}

/* ------------------------------------------------------------------------- */
/* AEAD interface for OCSimple with Areion256/512 and S, P, and SP           */

#ifdef CR_HAS_AREION

#include "../../perm/areion/areion.h"

int OCSimple256_512_S_Areion_init(AeadKey *aead_key,
                                  const uint8_t *key,
                                  size_t key_len) {
  const EM256 *em = EM_Areion256();
  OD512_DuplexChunk duplex_chunk = &perm_areion512_duplex_chunk;
  return OCSimple256_512_S_init(em, duplex_chunk, aead_key, key, key_len);
}

static const Aead ocsimple256_512_s_areion = {"AreionOCSimple-S",
                                              ocsimple_key_len,
                                              ocsimple_s_pubnonce_len,
                                              ocsimple_s_secnonce_len,
                                              ocsimple_s_overhead,
                                              OCSimple256_512_S_Areion_init,
                                              OCSimple256_512_seal,
                                              OCSimple256_512_open,
                                              NULL,
                                              NULL};

const Aead *Aead_OCSimple256_512_S_Areion() {
  return &ocsimple256_512_s_areion;
}

int OCSimple256_512_P_Areion_init(AeadKey *aead_key,
                                  const uint8_t *key,
                                  size_t key_len) {
  const EM256 *em = EM_Areion256();
  OD512_DuplexChunk duplex_chunk = &perm_areion512_duplex_chunk;
  return OCSimple256_512_P_init(em, duplex_chunk, aead_key, key, key_len);
}

static const Aead ocsimple256_512_p_areion = {"AreionOCSimple-P",
                                              ocsimple_key_len,
                                              ocsimple_p_pubnonce_len,
                                              ocsimple_p_secnonce_len,
                                              ocsimple_p_overhead,
                                              OCSimple256_512_P_Areion_init,
                                              OCSimple256_512_seal,
                                              OCSimple256_512_open,
                                              NULL,
                                              NULL};

const Aead *Aead_OCSimple256_512_P_Areion() {
  return &ocsimple256_512_p_areion;
}

#endif  // CR_HAS_AREION
