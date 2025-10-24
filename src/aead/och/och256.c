/*
    OCH with 256-bit OCT over generic AXU hash and CR hash.

    :copyright: (c) 2025 by OCH authors.
    :license: Creative Commons CC0 1.0
*/

#include "och256.h"

static OchChecksum update_checksum(OchChecksum chk, block *in) {
  // Take the first 128 bits of in
  return xor128(chk, in->u128[0]);
}

static int OCH256_S_init(const EM256 *oct,
                         const Hash *crhash,
                         const AxuHash *axuhash,
                         AeadKey *aead_key,
                         const uint8_t *key,
                         size_t key_len) {
  return OCH256_init(oct, crhash, axuhash, och_s_pubnonce_len,
                     och_s_secnonce_len, aead_key, key, key_len);
}

static int OCH256_P_init(const EM256 *oct,
                         const Hash *crhash,
                         const AxuHash *axuhash,
                         AeadKey *aead_key,
                         const uint8_t *key,
                         size_t key_len) {
  return OCH256_init(oct, crhash, axuhash, och_p_pubnonce_len,
                     och_p_secnonce_len, aead_key, key, key_len);
}

/**
 * Implementation of OCH256-Seal optimized for OCH-P.
 *
 * The generic |och256_seal| is less efficient for encrypting medium-sized
 * messages with OCH-P since it encrypts the first message block, and then
 * encrypts the rest of the blocks in groups of 4 or 1. So, if we had exactly 4
 * blocks or exactly 8 blocks, then they aren't aligned with OCH-P. This is not
 * a problem for OCH-S since the first block is the secret nonce and not the
 * message.
 *
 * This implementation is also simpler since there is no nonce-hiding, so we
 * don't need the one-block look-ahead to avoid overwriting the buffer.
 */
static int och256_p_seal(AeadKey *aead_key,
                         uint8_t *ct,
                         const uint8_t *msg,
                         size_t msg_len,
                         const uint8_t *ad,
                         size_t ad_len,
                         const uint8_t *pubnonce,
                         const uint8_t *secnonce) {
  int ret = 1;
  OCH256_ctx *ctx = (OCH256_ctx *)aead_key;
  Oct256State *oct_ctx = &ctx->oct_ctx;

  // initialize nonce pointers
  size_t secret_nonce_len = ctx->secnonce_len;
  size_t public_nonce_len = ctx->pubnonce_len;
  const uint8_t *public_nonce = pubnonce;
  const uint8_t *secret_nonce = secnonce;
  if (!((public_nonce_len == 32) && (secret_nonce_len == 0))) {
    assert(false);  // unimplemented
    return 0;
  }

  // we place the tag after the secret nonce and the encrypted message
  uint8_t *tag = ct + (secret_nonce_len + msg_len);
  size_t tag_len = och_tag_len;
  assert(tag_len == 32);

  // Derive an offset from the public nonce
  OctOffset n0_offset =
      Oct256_init_n0_offset(ctx->oct, &ctx->oct_ctx, public_nonce,
                            public_nonce_len, secret_nonce_len);

  // OCH-Tiny
  if ((secret_nonce_len + msg_len) < och256_perm_width) {
    assert(secret_nonce_len == 0);  // TODO: support other options
    assert(msg_len < och256_perm_width);
    const uint8_t *P = msg;
    size_t P_len = msg_len;
    // compute outer tag T^*
    ret &= OCH_compute_tag_tiny(ctx->crhash, &ctx->crhash_ctx, ctx->axuhash,
                                &ctx->axuhash_key, tag, P, P_len, ad, ad_len,
                                public_nonce, public_nonce_len, secret_nonce,
                                secret_nonce_len);
    // compute (N0, 1, star) offset
    OctOffset n0_1star_offset = xor256(n0_offset, oct_ctx->L[ntz(1)]);
    n0_1star_offset = xor256(n0_1star_offset, oct_ctx->Lstar);

    block Pad = load256(tag);
    ctx->oct->EM_encrypt(n0_1star_offset, &Pad);
    assert(P_len <= 31);
    for (int i = 0; i < P_len; i += 1) {
      ct[i] = Pad.u8[i] ^ P[i];
    }
    return ret;
  }

  // initialize checksum
  OchChecksum Checksum = zero128();

  int msg_idx = 0;  // offset in the msg buffer, updated on load
  int ct_idx = 0;   // offset in the ct buffer, updated on store
  int i = 1;        // i in pseudocode

  // Encrypt all blocks using the offset derived from the public nonce, since
  // there is no secret nonce.
  OctOffset n_offset = n0_offset;

// FIXME: optimize encryption in groups of eight
//        right now it has worse performance on hitch and offside
#if 0
  /* Encrypt in groups of eight */
  if (msg_len >= 8 * 32) {
    block Buf8[8] = {zero256(), zero256(), zero256(), zero256(),
                     zero256(), zero256(), zero256(), zero256()};
    OctOffset Off8[8] = {zero256(), zero256(), zero256(), zero256(),
                         zero256(), zero256(), zero256(), n_offset};

    for (; (msg_idx + (8 * 32)) <= msg_len; msg_idx += (8 * 32)) {
      assert(ct_idx <= msg_idx);

      Buf8[0] = load256(msg + msg_idx);
      Buf8[1] = load256(msg + msg_idx + 32);
      Buf8[2] = load256(msg + msg_idx + (2 * 32));
      Buf8[3] = load256(msg + msg_idx + (3 * 32));
      Checksum = update_checksum(Checksum, &Buf8[0]);
      Checksum = update_checksum(Checksum, &Buf8[1]);
      Checksum = update_checksum(Checksum, &Buf8[2]);
      Checksum = update_checksum(Checksum, &Buf8[3]);

      Buf8[4] = load256(msg + msg_idx + (4 * 32));
      Buf8[5] = load256(msg + msg_idx + (5 * 32));
      Buf8[6] = load256(msg + msg_idx + (6 * 32));
      Buf8[7] = load256(msg + msg_idx + (7 * 32));
      Checksum = update_checksum(Checksum, &Buf8[4]);
      Checksum = update_checksum(Checksum, &Buf8[5]);
      Checksum = update_checksum(Checksum, &Buf8[6]);
      Checksum = update_checksum(Checksum, &Buf8[7]);

      Off8[0] = xor256(Off8[7], oct_ctx->L[ntz(i)]);
      Off8[1] = xor256(Off8[0], oct_ctx->L[ntz(i + 1)]);
      Off8[2] = xor256(Off8[1], oct_ctx->L[ntz(i + 2)]);
      Off8[3] = xor256(Off8[2], oct_ctx->L[ntz(i + 3)]);
      Off8[4] = xor256(Off8[3], oct_ctx->L[ntz(i + 4)]);
      Off8[5] = xor256(Off8[4], oct_ctx->L[ntz(i + 5)]);
      Off8[6] = xor256(Off8[5], oct_ctx->L[ntz(i + 6)]);
      Off8[7] = xor256(Off8[6], oct_ctx->L[ntz(i + 7)]);

      ctx->oct->EM_encrypt_x8(Off8, Buf8);

      store256(ct + ct_idx, Buf8[0]);
      store256(ct + ct_idx + 32, Buf8[1]);
      store256(ct + ct_idx + (2 * 32), Buf8[2]);
      store256(ct + ct_idx + (3 * 32), Buf8[3]);
      store256(ct + ct_idx + (4 * 32), Buf8[4]);
      store256(ct + ct_idx + (5 * 32), Buf8[5]);
      store256(ct + ct_idx + (6 * 32), Buf8[6]);
      store256(ct + ct_idx + (7 * 32), Buf8[7]);
      ct_idx += (8 * 32);

      i += 8;
    }

    n_offset = Off8[7];
  } else
#endif
  if (msg_len >= 4 * 32) {
    /* Encrypt in groups of four */
    block Buf4[4] = {zero256(), zero256(), zero256(), zero256()};
    OctOffset Off4[4] = {zero256(), zero256(), zero256(), n_offset};

    for (; (msg_idx + (4 * 32)) <= msg_len; msg_idx += (4 * 32)) {
      assert(ct_idx <= msg_idx);

      Buf4[0] = load256(msg + msg_idx);
      Buf4[1] = load256(msg + msg_idx + 32);
      Buf4[2] = load256(msg + msg_idx + (2 * 32));
      Buf4[3] = load256(msg + msg_idx + (3 * 32));

      Checksum = update_checksum(Checksum, &Buf4[0]);
      Checksum = update_checksum(Checksum, &Buf4[1]);
      Checksum = update_checksum(Checksum, &Buf4[2]);
      Checksum = update_checksum(Checksum, &Buf4[3]);

      Off4[0] = xor256(Off4[3], oct_ctx->L[ntz(i)]);
      Off4[1] = xor256(Off4[0], oct_ctx->L[ntz(i + 1)]);
      Off4[2] = xor256(Off4[1], oct_ctx->L[ntz(i + 2)]);
      Off4[3] = xor256(Off4[2], oct_ctx->L[ntz(i + 3)]);

      ctx->oct->EM_encrypt_x4(Off4, Buf4);

      store256(ct + ct_idx, Buf4[0]);
      store256(ct + ct_idx + 32, Buf4[1]);
      store256(ct + ct_idx + (2 * 32), Buf4[2]);
      store256(ct + ct_idx + (3 * 32), Buf4[3]);
      ct_idx += (4 * 32);

      i += 4;
    }
    n_offset = Off4[3];

// FIXME: optimize encryption in groups of two
#if 0
  } else if (msg_len >= 2 * 32) {
    /* Encrypt in groups of two */
    block Buf2[2] = {zero256(), zero256()};
    OctOffset Off2[2] = {zero256(), n_offset};

    for (; (msg_idx + (2 * 32)) <= msg_len; msg_idx += (2 * 32)) {
      assert(ct_idx <= msg_idx);

      Buf2[0] = load256(msg + msg_idx);
      Buf2[1] = load256(msg + msg_idx + 32);

      Checksum = update_checksum(Checksum, &Buf2[0]);
      Checksum = update_checksum(Checksum, &Buf2[1]);

      ctx->oct->EM_encrypt(Off2[0], &Buf2[0]);
      ctx->oct->EM_encrypt(Off2[1], &Buf2[1]);

      Off2[0] = xor256(Off2[1], oct_ctx->L[ntz(i)]);
      Off2[1] = xor256(Off2[0], oct_ctx->L[ntz(i + 1)]);

      store256(ct + ct_idx, Buf2[0]);
      store256(ct + ct_idx + 32, Buf2[1]);
      ct_idx += (2 * 32);
      i += 2;
    }

    n_offset = Off2[1];
#endif
  }

  // Encrypt remaining blocks one-by-one
  if (msg_idx < msg_len) {
    block Pi = zero256();
    block Ci = zero256();
    for (; (msg_idx + 32) <= msg_len; msg_idx += 32) {
      assert(ct_idx <= msg_idx);
      Pi = load256(msg + msg_idx);
      Checksum = update_checksum(Checksum, &Pi);
      n_offset = xor256(n_offset, oct_ctx->L[ntz(i)]);
      Ci = Pi;
      ctx->oct->EM_encrypt(n_offset, &Ci);
      store256(ct + ct_idx, Ci);
      ct_idx += 32;

      i += 1;
    }
  }

  // If no partial block
  if (msg_idx == msg_len) {
    ret &= OCH_compute_tag_no_partial(
        ctx->crhash, &ctx->crhash_ctx, ctx->axuhash, &ctx->axuhash_key, tag,
        msg_len, ad, ad_len, public_nonce, public_nonce_len, secret_nonce,
        secret_nonce_len, Checksum);
    return ret;
  }

  // Handle partial block
  size_t Pstar_len = msg_len - msg_idx;
  assert(Pstar_len < 32);
  uint8_t extended_checksum[32] = {0};
  store128(extended_checksum, Checksum);
  size_t extended_checksum_len = 16;
  if (Pstar_len > 16) {
    extended_checksum_len = Pstar_len;
  }
  // encrypt partial block using Pad and update checksum
  n_offset = xor256(n_offset, oct_ctx->Lstar);
  block Pad = zero256();
  ctx->oct->EM_encrypt(n_offset, &Pad);
  for (int i = 0; i < Pstar_len; i += 1) {
    extended_checksum[i] ^= msg[msg_idx + i];
    ct[ct_idx + i] = Pad.u8[i] ^ msg[msg_idx + i];
  }

  ret &= OCH_compute_tag_with_partial(
      ctx->crhash, &ctx->crhash_ctx, ctx->axuhash, &ctx->axuhash_key, tag,
      msg_len, ad, ad_len, public_nonce, public_nonce_len, secret_nonce,
      secret_nonce_len, extended_checksum, extended_checksum_len);
  return ret;
}

/**
 * Generic implementation of OCH256-Seal, works for both OCH-P and OCH-S.
 */
static int och256_seal(AeadKey *aead_key,
                       uint8_t *ct,
                       const uint8_t *msg,
                       size_t msg_len,
                       const uint8_t *ad,
                       size_t ad_len,
                       const uint8_t *pubnonce,
                       const uint8_t *secnonce) {
  int ret = 1;
  OCH256_ctx *ctx = (OCH256_ctx *)aead_key;
  Oct256State *oct_ctx = &ctx->oct_ctx;

  // initialize nonce pointers
  size_t secret_nonce_len = ctx->secnonce_len;
  size_t public_nonce_len = ctx->pubnonce_len;
  const uint8_t *public_nonce = pubnonce;
  const uint8_t *secret_nonce = secnonce;
  if (!((public_nonce_len == 0) && (secret_nonce_len == 32)) &&
      !((public_nonce_len == 32) && (secret_nonce_len == 0))) {
    assert(false);  // unimplemented
    return 0;
  }

  // we place the tag after the secret nonce and the encrypted message
  uint8_t *tag = ct + (secret_nonce_len + msg_len);
  size_t tag_len = och_tag_len;
  assert(tag_len == 32);

  // Derive an offset from the public nonce
  OctOffset n0_offset =
      Oct256_init_n0_offset(ctx->oct, &ctx->oct_ctx, public_nonce,
                            public_nonce_len, secret_nonce_len);

  // OCH-Tiny
  if ((secret_nonce_len + msg_len) < och256_perm_width) {
    assert(secret_nonce_len == 0);  // TODO: support other options
    assert(msg_len < och256_perm_width);
    const uint8_t *P = msg;
    size_t P_len = msg_len;
    // compute outer tag T^*
    ret &= OCH_compute_tag_tiny(ctx->crhash, &ctx->crhash_ctx, ctx->axuhash,
                                &ctx->axuhash_key, tag, P, P_len, ad, ad_len,
                                public_nonce, public_nonce_len, secret_nonce,
                                secret_nonce_len);
    // compute (N0, 1, star) offset
    OctOffset n0_1star_offset = xor256(n0_offset, oct_ctx->L[ntz(1)]);
    n0_1star_offset = xor256(n0_1star_offset, oct_ctx->Lstar);

    block Pad = load256(tag);
    ctx->oct->EM_encrypt(n0_1star_offset, &Pad);
    assert(P_len <= 31);
    for (int i = 0; i < P_len; i += 1) {
      ct[i] = Pad.u8[i] ^ P[i];
    }
    return ret;
  }

  // initialize checksum
  OchChecksum Checksum = zero128();

  // NOTE: The caller may reuse buffers, ct = msg, so always need to read one
  //       block ahead to avoid corrupting buffers. This is not a problem in
  //       OCB because it does not do nonce hiding.

  int msg_idx = 0;  // offset in the msg buffer, updated on load
  int ct_idx = 0;   // offset in the ct buffer, updated on store
  int i = 1;        // i in pseudocode

  // FIXME: be smarter for OCH_P

  // Encrypt the first block using the offset derived from the public nonce
  assert((secret_nonce_len + msg_len) >= och256_perm_width);
  block P1 = zero256();
  if ((public_nonce_len == 0) && (secret_nonce_len == 32)) {
    // secret_nonce fills the entire first block
    P1 = load256(secret_nonce);
  } else if ((public_nonce_len == 32) && (secret_nonce_len == 0)) {
    // first block is the first block of the message
    assert(msg_len >= 32);
    P1 = load256(msg);
    msg_idx += 32;
  } else {
    assert(false);  // unimplemented
    return 0;
  }

  Checksum = update_checksum(Checksum, &P1);
  n0_offset = xor256(n0_offset, oct_ctx->L[ntz(1)]);
  block C1 = P1;
  ctx->oct->EM_encrypt(n0_offset, &C1);
  i += 1;

  // Derive an offset from the full nonce
  OctOffset n_offset =
      Oct256_init_n_offset(ctx->oct, &ctx->oct_ctx, public_nonce,
                           public_nonce_len, secret_nonce, secret_nonce_len);
  n_offset = xor256(n_offset, oct_ctx->L[ntz(1)]);

  // Encrypt the rest of the blocks using the offset derived from the full nonce

  assert(i == 2);

  block Ci = zero256();
  // // TODO: implement this
  // if (msg_len >= 8 * 32) {
  //   /* Encrypt in groups of eight */
  // } else
  if (msg_len >= 4 * 32) {
    /* Encrypt in groups of four */

    block Pi4[4] = {zero256(), zero256(), zero256(), zero256()};
    block Ci4[4] = {zero256(), zero256(), zero256(), C1};
    OctOffset Off4[4] = {zero256(), zero256(), zero256(), n_offset};

    for (; (msg_idx + (4 * 32)) <= msg_len; msg_idx += (4 * 32)) {
      assert(ct_idx <= msg_idx);

      Pi4[0] = load256(msg + msg_idx);
      store256(ct + ct_idx, Ci4[3]);
      ct_idx += 32;

      Pi4[1] = load256(msg + msg_idx + 32);
      Pi4[2] = load256(msg + msg_idx + (2 * 32));
      Pi4[3] = load256(msg + msg_idx + (3 * 32));

      Checksum = update_checksum(Checksum, &Pi4[0]);
      Checksum = update_checksum(Checksum, &Pi4[1]);
      Checksum = update_checksum(Checksum, &Pi4[2]);
      Checksum = update_checksum(Checksum, &Pi4[3]);

      Off4[0] = xor256(Off4[3], oct_ctx->L[ntz(i)]);
      Off4[1] = xor256(Off4[0], oct_ctx->L[ntz(i + 1)]);
      Off4[2] = xor256(Off4[1], oct_ctx->L[ntz(i + 2)]);
      Off4[3] = xor256(Off4[2], oct_ctx->L[ntz(i + 3)]);

      Ci4[0] = Pi4[0];
      Ci4[1] = Pi4[1];
      Ci4[2] = Pi4[2];
      Ci4[3] = Pi4[3];

      ctx->oct->EM_encrypt_x4(Off4, Ci4);

      store256(ct + ct_idx, Ci4[0]);
      store256(ct + ct_idx + 32, Ci4[1]);
      store256(ct + ct_idx + (2 * 32), Ci4[2]);
      ct_idx += (3 * 32);

      i += 4;
    }

    Ci = Ci4[3];
    n_offset = Off4[3];
  } else {
    Ci = C1;
  }

  block Pi = zero256();
  // Encrypt remaining blocks one-by-one
  for (; (msg_idx + 32) <= msg_len; msg_idx += 32) {
    assert(ct_idx <= msg_idx);
    Pi = load256(msg + msg_idx);
    store256(ct + ct_idx, Ci);
    ct_idx += 32;
    Checksum = update_checksum(Checksum, &Pi);
    n_offset = xor256(n_offset, oct_ctx->L[ntz(i)]);
    Ci = Pi;
    ctx->oct->EM_encrypt(n_offset, &Ci);

    i += 1;
  }

  // If no partial block
  if (msg_idx == msg_len) {
    // store remaining block
    store256(ct + ct_idx, Ci);
    ct_idx += 32;
    ret &= OCH_compute_tag_no_partial(
        ctx->crhash, &ctx->crhash_ctx, ctx->axuhash, &ctx->axuhash_key, tag,
        msg_len, ad, ad_len, public_nonce, public_nonce_len, secret_nonce,
        secret_nonce_len, Checksum);
    return ret;
  }

  // Handle partial block
  uint8_t Pstar[32] = {0};
  size_t Pstar_len = msg_len - msg_idx;
  assert(Pstar_len < 32);
  uint8_t extended_checksum[32] = {0};
  store128(extended_checksum, Checksum);
  size_t extended_checksum_len = 16;
  if (Pstar_len > 16) {
    extended_checksum_len = Pstar_len;
  }
  // load partial block
  assert(msg_idx + Pstar_len == msg_len);
  for (int i = 0; i < Pstar_len; i += 1) {
    Pstar[i] = msg[msg_idx + i];
    extended_checksum[i] ^= Pstar[i];
  }
  // store last full block
  store256(ct + ct_idx, Ci);
  ct_idx += 32;
  // encrypt partial block using Pad
  n_offset = xor256(n_offset, oct_ctx->Lstar);
  block Pad = zero256();
  ctx->oct->EM_encrypt(n_offset, &Pad);
  for (int i = 0; i < Pstar_len; i += 1) {
    ct[ct_idx + i] = Pad.u8[i] ^ Pstar[i];
  }

  ret &= OCH_compute_tag_with_partial(
      ctx->crhash, &ctx->crhash_ctx, ctx->axuhash, &ctx->axuhash_key, tag,
      msg_len, ad, ad_len, public_nonce, public_nonce_len, secret_nonce,
      secret_nonce_len, extended_checksum, extended_checksum_len);
  return ret;
}

static int och256_open(AeadKey *aead_key,
                       uint8_t *msg,
                       uint8_t *secnonce,
                       const uint8_t *ct,
                       size_t ct_len,
                       const uint8_t *ad,
                       size_t ad_len,
                       const uint8_t *pubnonce) {
  int ret = 1;
  OCH256_ctx *ctx = (OCH256_ctx *)aead_key;
  Oct256State *oct_ctx = &ctx->oct_ctx;

  // initialize nonce pointers
  size_t secret_nonce_len = ctx->secnonce_len;
  size_t public_nonce_len = ctx->pubnonce_len;
  const uint8_t *public_nonce = pubnonce;
  uint8_t *secret_nonce = secnonce;
  if (!((public_nonce_len == 0) && (secret_nonce_len == 32)) &&
      !((public_nonce_len == 32) && (secret_nonce_len == 0))) {
    assert(false);  // unimplemented
    return 0;
  }

  size_t tag_len = och_tag_len;
  assert(tag_len == 32);
  size_t ctcore_len = ct_len - tag_len;
  size_t msg_len = ctcore_len - secret_nonce_len;
  const uint8_t *given_tag = ct + ctcore_len;
  assert(ct_len == msg_len + tag_len + secret_nonce_len);

  // Derive an offset from the public nonce
  OctOffset n0_offset =
      Oct256_init_n0_offset(ctx->oct, &ctx->oct_ctx, public_nonce,
                            public_nonce_len, secret_nonce_len);

  // OCH-Tiny
  if ((msg_len + secret_nonce_len) < och256_perm_width) {
    assert(secret_nonce_len == 0);  // TODO: support other options
    assert(msg_len < och256_perm_width);
    uint8_t *P = msg;
    size_t P_len = msg_len;

    // compute (N0, 1, star) offset
    OctOffset n0_1star_offset = xor256(n0_offset, oct_ctx->L[ntz(1)]);
    n0_1star_offset = xor256(n0_1star_offset, oct_ctx->Lstar);

    block Pad = load256(given_tag);
    ctx->oct->EM_encrypt(n0_1star_offset, &Pad);
    assert(P_len <= 31);
    for (int i = 0; i < P_len; i += 1) {
      P[i] = Pad.u8[i] ^ ct[i];
    }

    // compute expected outer tag T_d^*
    uint8_t expected_tag[32] = {0};
    ret &= OCH_compute_tag_tiny(ctx->crhash, &ctx->crhash_ctx, ctx->axuhash,
                                &ctx->axuhash_key, expected_tag, P, P_len, ad,
                                ad_len, public_nonce, public_nonce_len,
                                secret_nonce, secret_nonce_len);
    ret &= constant_time_compare(expected_tag, given_tag, tag_len);
    return ret;
  }

  // initialize checksum
  OchChecksum Checksum = zero128();

  int ct_idx = 0;   // offset in the ct buffer, updated on load
  int msg_idx = 0;  // offset in the msg buffer, updated on store
  int i = 1;        // i in pseudocode

  // Decrypt the first block using the offset derived from the public nonce
  assert((ct_len) >= och256_perm_width);
  block C1 = load256(ct);
  ct_idx += 32;

  n0_offset = xor256(n0_offset, oct_ctx->L[ntz(1)]);
  block P1 = C1;
  ctx->oct->EM_decrypt(n0_offset, &P1);
  Checksum = update_checksum(Checksum, &P1);
  i += 1;

  if ((public_nonce_len == 0) && (secret_nonce_len == 32)) {
    // secret_nonce fills the entire first block
    store256(secret_nonce, P1);
  } else if ((public_nonce_len == 32) && (secret_nonce_len == 0)) {
    // first block is the first block of the message
    assert(msg_len >= 32);
    store256(msg, P1);
    msg_idx += 32;
  } else {
    assert(false);  // unimplemented
    return 0;
  }

  // Derive an offset from the full nonce
  OctOffset n_offset =
      Oct256_init_n_offset(ctx->oct, &ctx->oct_ctx, public_nonce,
                           public_nonce_len, secret_nonce, secret_nonce_len);
  n_offset = xor256(n_offset, oct_ctx->L[ntz(1)]);

  assert(i == 2);
  assert(ct_idx == 32);
  // Decrypt blocks one-by-one
  block Pi = zero256();
  block Ci = zero256();
  for (; (ct_idx + 32) <= ctcore_len; ct_idx += 32) {
    Ci = load256(ct + ct_idx);
    n_offset = xor256(n_offset, oct_ctx->L[ntz(i)]);
    Pi = Ci;
    ctx->oct->EM_decrypt(n_offset, &Pi);
    Checksum = update_checksum(Checksum, &Pi);
    i += 1;

    store256(msg + msg_idx, Pi);
    msg_idx += 32;
  }

  // If no partial block
  if (ct_idx == ctcore_len) {
    // compute expected outer tag T_d^*
    uint8_t expected_tag[32] = {0};
    ret &= OCH_compute_tag_no_partial(
        ctx->crhash, &ctx->crhash_ctx, ctx->axuhash, &ctx->axuhash_key,
        expected_tag, msg_len, ad, ad_len, public_nonce, public_nonce_len,
        secret_nonce, secret_nonce_len, Checksum);
    ret &= constant_time_compare(expected_tag, given_tag, tag_len);
    return ret;
  }

  // Handle partial block
  size_t Pstar_len = ctcore_len - ct_idx;
  assert(Pstar_len < 32);
  uint8_t extended_checksum[32] = {0};
  store128(extended_checksum, Checksum);
  size_t extended_checksum_len = 16;
  if (Pstar_len > 16) {
    extended_checksum_len = Pstar_len;
  }
  // decrypt partial block using Pad
  n_offset = xor256(n_offset, oct_ctx->Lstar);
  block Pad = zero256();
  ctx->oct->EM_encrypt(n_offset, &Pad);
  assert(msg_idx + Pstar_len == msg_len);
  assert(ct_idx + Pstar_len == ctcore_len);
  for (int j = 0; j < Pstar_len; j += 1) {
    msg[msg_idx + j] = Pad.u8[j] ^ ct[ct_idx + j];
    extended_checksum[j] ^= msg[msg_idx + j];
  }

  uint8_t expected_tag[32] = {0};
  ret &= OCH_compute_tag_with_partial(
      ctx->crhash, &ctx->crhash_ctx, ctx->axuhash, &ctx->axuhash_key,
      expected_tag, msg_len, ad, ad_len, public_nonce, public_nonce_len,
      secret_nonce, secret_nonce_len, extended_checksum, extended_checksum_len);
  ret &= constant_time_compare(expected_tag, given_tag, tag_len);
  return ret;
}

/* ------------------------------------------------------------------------- */
/* AEAD interface for OCH_S-Sparkle and OCH_P-Sparkle                        */

int aead_och_s_sparkle_init(AeadKey *aead_key,
                            const uint8_t *key,
                            size_t key_len) {
  return OCH256_S_init(EM_Sparkle256(), Hash_Sparkle512Sponge(),
                       AxuHash_X2Polyval(), aead_key, key, key_len);
}

int aead_och_p_sparkle_init(AeadKey *aead_key,
                            const uint8_t *key,
                            size_t key_len) {
  return OCH256_P_init(EM_Sparkle256(), Hash_Sparkle512Sponge(),
                       AxuHash_X2Polyval(), aead_key, key, key_len);
}

static const Aead och_s_sparkle = {"SparkleOCH-S",
                                   och_key_len,
                                   och_s_pubnonce_len,
                                   och_s_secnonce_len,
                                   och_s_overhead,
                                   aead_och_s_sparkle_init,
                                   och256_seal,
                                   och256_open,
                                   NULL,
                                   NULL};

static const Aead och_p_sparkle = {"SparkleOCH-P",
                                   och_key_len,
                                   och_p_pubnonce_len,
                                   och_p_secnonce_len,
                                   och_p_overhead,
                                   aead_och_p_sparkle_init,
                                   och256_p_seal,
                                   och256_open,
                                   NULL,
                                   NULL};

const Aead *Aead_och_s_sparkle() {
  return &och_s_sparkle;
}

const Aead *Aead_och_p_sparkle() {
  return &och_p_sparkle;
}

/* ------------------------------------------------------------------------- */
/* AEAD interface for OCH_S-Areion and OCH_P-Areion                        */

#ifdef CR_HAS_AREION

int aead_och_s_Areion_init(AeadKey *aead_key,
                           const uint8_t *key,
                           size_t key_len) {
  return OCH256_S_init(EM_Areion256(), Hash_Areion512Sponge(),
                       AxuHash_X2Polyval(), aead_key, key, key_len);
}

int aead_och_p_Areion_init(AeadKey *aead_key,
                           const uint8_t *key,
                           size_t key_len) {
  return OCH256_P_init(EM_Areion256(), Hash_Areion512Sponge(),
                       AxuHash_X2Polyval(), aead_key, key, key_len);
}

static const Aead och_s_areion = {"AreionOCH-S",
                                  och_key_len,
                                  och_s_pubnonce_len,
                                  och_s_secnonce_len,
                                  och_s_overhead,
                                  aead_och_s_Areion_init,
                                  och256_seal,
                                  och256_open,
                                  NULL,
                                  NULL};

static const Aead och_p_areion = {"AreionOCH-P",
                                  och_key_len,
                                  och_p_pubnonce_len,
                                  och_p_secnonce_len,
                                  och_p_overhead,
                                  aead_och_p_Areion_init,
                                  och256_p_seal,
                                  och256_open,
                                  NULL,
                                  NULL};

const Aead *Aead_och_s_areion() {
  return &och_s_areion;
}

const Aead *Aead_och_p_areion() {
  return &och_p_areion;
}

int aead_ocs_s_Areion_init(AeadKey *aead_key,
                           const uint8_t *key,
                           size_t key_len) {
  return OCH256_S_init(EM_Areion256(), Hash_ODAreion512(), AxuHash_X2Polyval(),
                       aead_key, key, key_len);
}

int aead_ocs_p_Areion_init(AeadKey *aead_key,
                           const uint8_t *key,
                           size_t key_len) {
  return OCH256_P_init(EM_Areion256(), Hash_ODAreion512(), AxuHash_X2Polyval(),
                       aead_key, key, key_len);
}

static const Aead ocs_s_areion = {"AreionOCS-S",
                                  och_key_len,
                                  och_s_pubnonce_len,
                                  och_s_secnonce_len,
                                  och_s_overhead,
                                  aead_ocs_s_Areion_init,
                                  och256_seal,
                                  och256_open,
                                  NULL,
                                  NULL};

static const Aead ocs_p_areion = {"AreionOCS-P",
                                  och_key_len,
                                  och_p_pubnonce_len,
                                  och_p_secnonce_len,
                                  och_p_overhead,
                                  aead_ocs_p_Areion_init,
                                  och256_p_seal,
                                  och256_open,
                                  NULL,
                                  NULL};

const Aead *Aead_ocs_s_areion() {
  return &ocs_s_areion;
}

const Aead *Aead_ocs_p_areion() {
  return &ocs_p_areion;
}

#endif