#include <cryptography-run/cipher.h>

#ifndef __VAES__
#error "rijndael256ecb implementation uses vaes"
#endif
#include <immintrin.h>

static const uint8_t rijndael256ecb_key_len = 32;
static const uint8_t rijndael256ecb_block_len = 32;

// Adapted from
// https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf

#define R256_ROUNDS 14

#define AES256_KEYEXPAND_1(rnum, rcon)                                  \
  /* temp0 = last last round key */                                     \
  /* temp1 = last round key */                                          \
  /* xor with last last round key shifted by words */                   \
  scratch0 = _mm_slli_si128(temp0, 4);                                  \
  temp0 = _mm_xor_si128(temp0, scratch0);                               \
  scratch0 = _mm_slli_si128(scratch0, 4);                               \
  temp0 = _mm_xor_si128(temp0, scratch0);                               \
  scratch0 = _mm_slli_si128(scratch0, 4);                               \
  temp0 = _mm_xor_si128(temp0, scratch0);                               \
  /* xor each word with RotWord(SubWord(last_round_key[3])) xor rcon */ \
  scratch1 = _mm_aeskeygenassist_si128(temp1, rcon);                    \
  scratch1 = _mm_shuffle_epi32(scratch1, 0xff);                         \
  temp0 = _mm_xor_si128(temp0, scratch1);                               \
  round_keys[rnum] = temp0;

#define AES256_KEYEXPAND_2(rnum, rcon)                \
  /* temp0 = last round key */                        \
  /* temp1 = last last round key */                   \
  /* xor with last last round key shifted by words */ \
  scratch0 = _mm_slli_si128(temp1, 4);                \
  temp1 = _mm_xor_si128(temp1, scratch0);             \
  scratch0 = _mm_slli_si128(scratch0, 4);             \
  temp1 = _mm_xor_si128(temp1, scratch0);             \
  scratch0 = _mm_slli_si128(scratch0, 4);             \
  temp1 = _mm_xor_si128(temp1, scratch0);             \
  /* xor each word with SubWord(last_round_key[3]) */ \
  scratch1 = _mm_aeskeygenassist_si128(temp0, rcon);  \
  scratch1 = _mm_shuffle_epi32(scratch1, 0xaa);       \
  temp1 = _mm_xor_si128(temp1, scratch1);             \
  round_keys[rnum] = temp1;

/**
 * Expand |key| into 14 256-bit round keys (represented as an array of 28
 * 128-bit numbers), for encryption.
 *
 * Defined in Page 15 of
 * https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
 *
 * Round constants are defined in Table 5 of
 * https://doi.org/10.6028/NIST.FIPS.197-upd1
 */
void rijndael256_key_expansion_encrypt(const uint8_t *key,
                                       __m128i round_keys[30]) {
  // This function operates on 32-bit words.
  // The first 8 words---the first two round keys---are the given key.
  __m128i temp0 = _mm_loadu_si128((__m128i *)key);
  __m128i temp1 = _mm_loadu_si128((__m128i *)(key + 16));
  round_keys[0] = temp0;
  round_keys[1] = temp1;

  // The remaining 52 words---the next 13 round keys---are computed as follows
  // temp = w[i-1]
  // if (i mod 8) == 0:
  //   w[i] = SubWord(RotWord(temp)) xor Rcon[i/8]
  // else if (i mod 8) == 4:
  //   temp = SubWord(temp)
  // w[i] = w[i-8] xor temp
  //
  // Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
  // 0xd8, 0xab, 0x4d]

  // keygenassist((x3, x2, x1, x0), rcon) returns
  // (RotWord(SubWord(x3)) xor rcon,
  //  SubWord(x3),
  //  RotWord(SubWord(x1)) xor rcon,
  //  SubWord(x1))

  __m128i scratch0 = {0, 0};
  __m128i scratch1 = {0, 0};
  AES256_KEYEXPAND_1(2, 0x01);
  AES256_KEYEXPAND_2(3, 0x01);
  AES256_KEYEXPAND_1(4, 0x02);
  AES256_KEYEXPAND_2(5, 0x02);
  AES256_KEYEXPAND_1(6, 0x04);
  AES256_KEYEXPAND_2(7, 0x04);
  AES256_KEYEXPAND_1(8, 0x08);
  AES256_KEYEXPAND_2(9, 0x08);
  AES256_KEYEXPAND_1(10, 0x10);
  AES256_KEYEXPAND_2(11, 0x10);
  AES256_KEYEXPAND_1(12, 0x20);
  AES256_KEYEXPAND_2(13, 0x20);
  AES256_KEYEXPAND_1(14, 0x40);
  AES256_KEYEXPAND_2(15, 0x40);
  AES256_KEYEXPAND_1(16, 0x80);
  AES256_KEYEXPAND_2(17, 0x80);
  AES256_KEYEXPAND_1(18, 0x1b);
  AES256_KEYEXPAND_2(19, 0x1b);
  AES256_KEYEXPAND_1(20, 0x36);
  AES256_KEYEXPAND_2(21, 0x36);
  AES256_KEYEXPAND_1(22, 0x6c);
  AES256_KEYEXPAND_2(23, 0x6c);
  AES256_KEYEXPAND_1(24, 0xd8);
  AES256_KEYEXPAND_2(25, 0xd8);
  AES256_KEYEXPAND_1(26, 0xab);
  AES256_KEYEXPAND_2(27, 0xab);
  AES256_KEYEXPAND_1(28, 0x4d);
  AES256_KEYEXPAND_2(29, 0x4d);
}

/**
 * Expand |key| into 14 128-bit round keys, for decryption.
 *
 * Defined in Algorithm 5 of https://doi.org/10.6028/NIST.FIPS.197-upd1
 */
void rijndael256_key_expansion_decrypt(const uint8_t *key,
                                       __m128i round_keys[30]) {
  rijndael256_key_expansion_encrypt(key, round_keys);
  // Apply InverseMixColumns to keys 1 to 13
  for (int i = 2; i < 28; i++) {
    round_keys[i] = _mm_aesimc_si128(round_keys[i]);
  }
}

/**
 * Encrypt with AES256 in ECB mode.
 *
 * Rijndael256.Encrypt is defined in Page 16 of
 * https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
 *
 * @return one on success, zero otherwise
 */
static int rijndael256ecb_encrypt(uint8_t *ct,
                                  const uint8_t *msg,
                                  const size_t msg_len,
                                  const uint8_t *key) {
  if ((msg_len % 32) != 0) {
    return 0;
  }
  size_t num_blocks = msg_len / 16;
  __m128i *msg_blocks = (__m128i *)msg;
  __m128i *ct_blocks = (__m128i *)ct;

  __m128i round_keys[30] = {0};
  rijndael256_key_expansion_encrypt(key, round_keys);

  // Adapted from Figure 30 of
  // https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf

  // Rijndael256 does shifting over a 4x8 matrix, compared to 4x4 for AES256.
  // See Figure 1 of
  // https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
  // We account for this with a conditional blend
  __m128i ShiftBlendMask =
      _mm_set_epi32(0x80000000, 0x80800000, 0x80800000, 0x80808000);

  // Shift offsets for Rijndael256 are (1,3,4), compared to (1,2,3) for AES256.
  // See Table 2 of
  // https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf
  // We account for this with a conditional shuffle
  __m128i ShiftShuffleMask =
      _mm_set_epi32(0x03020d0c, 0x0f0e0908, 0x0b0a0504, 0x07060100);

  for (size_t i = 0; i < num_blocks; i += 2) {
    __m128i state0 = _mm_loadu_si128(&msg_blocks[i]);
    __m128i state1 = _mm_loadu_si128(&msg_blocks[i + 1]);
    state0 = _mm_xor_si128(state0, round_keys[0]);
    state1 = _mm_xor_si128(state1, round_keys[1]);
    for (int j = 1; j < R256_ROUNDS; j++) {
      __m128i scratch0 = _mm_blendv_epi8(state0, state1, ShiftBlendMask);
      __m128i scratch1 = _mm_blendv_epi8(state1, state0, ShiftBlendMask);
      scratch0 = _mm_shuffle_epi8(scratch0, ShiftShuffleMask);
      scratch1 = _mm_shuffle_epi8(scratch1, ShiftShuffleMask);
      state0 = _mm_aesenc_si128(scratch0, round_keys[2 * j]);
      state1 = _mm_aesenc_si128(scratch1, round_keys[2 * j + 1]);
    }
    __m128i scratch0 = _mm_blendv_epi8(state0, state1, ShiftBlendMask);
    __m128i scratch1 = _mm_blendv_epi8(state1, state0, ShiftBlendMask);
    state0 = _mm_shuffle_epi8(scratch0, ShiftShuffleMask);
    state1 = _mm_shuffle_epi8(scratch1, ShiftShuffleMask);
    state0 = _mm_aesenclast_si128(state0, round_keys[2 * R256_ROUNDS]);
    state1 = _mm_aesenclast_si128(state1, round_keys[2 * R256_ROUNDS + 1]);
    _mm_storeu_si128(&ct_blocks[i], state0);
    _mm_storeu_si128(&ct_blocks[i + 1], state1);
  }
  return 1;
}

static int rijndael256ecb_decrypt(uint8_t *msg,
                                  const uint8_t *ct,
                                  const size_t ct_len,
                                  const uint8_t *key) {
  // FIXME: Implement this.
  return 0;
}

static const BlockCipher rijndael256ecb = {
    "Rijndael256-ECB", rijndael256ecb_key_len, rijndael256ecb_block_len,
    rijndael256ecb_encrypt, rijndael256ecb_decrypt};

const BlockCipher *BlockCipher_rijndael256ecb() {
  return &rijndael256ecb;
}
