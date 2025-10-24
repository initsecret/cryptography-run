/*
 * Even-Mansour with a 256-bit permutation
 *
 * :copyright: (c) 2025 by OCH authors.
 * :license: Creative Commons CC0 1.0
 */

#include "em256.h"

static inline block EM256_xor_offset(const EMOffset offset, const block *in) {
  return xor256(offset, *in);
}
/* ------------------------------------------------------------------------- */
/* AEAD interface for OCT-Sparkle256                                         */

#include "../../perm/sparkle/sparkle.h"

static void EM_Sparkle256_encrypt(const EMOffset offset, block *inout) {
  *inout = EM256_xor_offset(offset, inout);
  perm_sparkle256big_forward(inout);
  *inout = EM256_xor_offset(offset, inout);
}

static void EM_Sparkle256_decrypt(const EMOffset offset, block *inout) {
  *inout = EM256_xor_offset(offset, inout);
  perm_sparkle256big_backward(inout);
  *inout = EM256_xor_offset(offset, inout);
}

static void EM_Sparkle256_encrypt_x4(const EMOffset offset[4], block inout[4]) {
  inout[0] = EM256_xor_offset(offset[0], &inout[0]);
  inout[1] = EM256_xor_offset(offset[1], &inout[1]);
  inout[2] = EM256_xor_offset(offset[2], &inout[2]);
  inout[3] = EM256_xor_offset(offset[3], &inout[3]);
  perm_sparkle256big_forward(&inout[0]);
  perm_sparkle256big_forward(&inout[1]);
  perm_sparkle256big_forward(&inout[2]);
  perm_sparkle256big_forward(&inout[3]);
  inout[0] = EM256_xor_offset(offset[0], &inout[0]);
  inout[1] = EM256_xor_offset(offset[1], &inout[1]);
  inout[2] = EM256_xor_offset(offset[2], &inout[2]);
  inout[3] = EM256_xor_offset(offset[3], &inout[3]);
}

static void EM_Sparkle256_encrypt_x8(const EMOffset offset[4], block inout[4]) {
  inout[0] = EM256_xor_offset(offset[0], &inout[0]);
  inout[1] = EM256_xor_offset(offset[1], &inout[1]);
  inout[2] = EM256_xor_offset(offset[2], &inout[2]);
  inout[3] = EM256_xor_offset(offset[3], &inout[3]);
  inout[4] = EM256_xor_offset(offset[4], &inout[4]);
  inout[5] = EM256_xor_offset(offset[5], &inout[5]);
  inout[6] = EM256_xor_offset(offset[6], &inout[6]);
  inout[7] = EM256_xor_offset(offset[7], &inout[7]);
  perm_sparkle256big_forward(&inout[0]);
  perm_sparkle256big_forward(&inout[1]);
  perm_sparkle256big_forward(&inout[2]);
  perm_sparkle256big_forward(&inout[3]);
  perm_sparkle256big_forward(&inout[4]);
  perm_sparkle256big_forward(&inout[5]);
  perm_sparkle256big_forward(&inout[6]);
  perm_sparkle256big_forward(&inout[7]);
  inout[0] = EM256_xor_offset(offset[0], &inout[0]);
  inout[1] = EM256_xor_offset(offset[1], &inout[1]);
  inout[2] = EM256_xor_offset(offset[2], &inout[2]);
  inout[3] = EM256_xor_offset(offset[3], &inout[3]);
  inout[4] = EM256_xor_offset(offset[4], &inout[4]);
  inout[5] = EM256_xor_offset(offset[5], &inout[5]);
  inout[6] = EM256_xor_offset(offset[6], &inout[6]);
  inout[7] = EM256_xor_offset(offset[7], &inout[7]);
}

static const EM256 EMSparkle256 = {
    "OCT-Sparkle256",         {0x05, 0x01},
    EM_Sparkle256_encrypt,    EM_Sparkle256_decrypt,
    EM_Sparkle256_encrypt_x4, EM_Sparkle256_encrypt_x8,
};

const EM256 *EM_Sparkle256() {
  return &EMSparkle256;
}

/* ------------------------------------------------------------------------- */
/* AEAD interface for OCT-Areion256                                         */

#ifdef CR_HAS_AREION

#include "../../perm/areion/areion.h"

static void EM_Areion256_encrypt(const EMOffset offset, block *inout) {
  *inout = EM256_xor_offset(offset, inout);
  perm_areion256_forward(inout);
  *inout = EM256_xor_offset(offset, inout);
}

static void EM_Areion256_decrypt(const EMOffset offset, block *inout) {
  *inout = EM256_xor_offset(offset, inout);
  perm_areion256_backward(inout);
  *inout = EM256_xor_offset(offset, inout);
}

static void EM_Areion256_encrypt_x4(const EMOffset offset[4], block inout[4]) {
  inout[0] = EM256_xor_offset(offset[0], &inout[0]);
  inout[1] = EM256_xor_offset(offset[1], &inout[1]);
  inout[2] = EM256_xor_offset(offset[2], &inout[2]);
  inout[3] = EM256_xor_offset(offset[3], &inout[3]);
  perm_areion256_forward_x4(inout);
  inout[0] = EM256_xor_offset(offset[0], &inout[0]);
  inout[1] = EM256_xor_offset(offset[1], &inout[1]);
  inout[2] = EM256_xor_offset(offset[2], &inout[2]);
  inout[3] = EM256_xor_offset(offset[3], &inout[3]);
}

static void EM_Areion256_encrypt_x8(const EMOffset offset[4], block inout[4]) {
  inout[0] = EM256_xor_offset(offset[0], &inout[0]);
  inout[1] = EM256_xor_offset(offset[1], &inout[1]);
  inout[2] = EM256_xor_offset(offset[2], &inout[2]);
  inout[3] = EM256_xor_offset(offset[3], &inout[3]);
  inout[4] = EM256_xor_offset(offset[4], &inout[4]);
  inout[5] = EM256_xor_offset(offset[5], &inout[5]);
  inout[6] = EM256_xor_offset(offset[6], &inout[6]);
  inout[7] = EM256_xor_offset(offset[7], &inout[7]);
  perm_areion256_forward_x8(inout);
  inout[0] = EM256_xor_offset(offset[0], &inout[0]);
  inout[1] = EM256_xor_offset(offset[1], &inout[1]);
  inout[2] = EM256_xor_offset(offset[2], &inout[2]);
  inout[3] = EM256_xor_offset(offset[3], &inout[3]);
  inout[4] = EM256_xor_offset(offset[4], &inout[4]);
  inout[5] = EM256_xor_offset(offset[5], &inout[5]);
  inout[6] = EM256_xor_offset(offset[6], &inout[6]);
  inout[7] = EM256_xor_offset(offset[7], &inout[7]);
}

static const EM256 EMAreion256 = {
    "OCT-Areion256",         {0x05, 0x02},
    EM_Areion256_encrypt,    EM_Areion256_decrypt,
    EM_Areion256_encrypt_x4, EM_Areion256_encrypt_x8,
};

const EM256 *EM_Areion256() {
  return &EMAreion256;
}

#endif