#include <cryptography-run/cipher.h>

#ifndef __VAES__
#error "aes256ecb implementation uses vaes"
#endif
#include <immintrin.h>

static const uint8_t aes256ecb_key_len = 32;
static const uint8_t aes256ecb_block_len = 16;

// Adapted from
// https://www.intel.com/content/dam/doc/white-paper/advanced-encryption-standard-new-instructions-set-paper.pdf

#define AES256_ROUNDS 14

#define AES256_ENCRYPT_MODE 0x00
#define AES256_DECRYPT_MODE 0x01

typedef struct {
  __m128i round_keys[15];
  uint8_t mode;
} aes256_ctx;

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
 * Expand |key| into 14 128-bit round keys, for encryption.
 *
 * Defined in Algorithm 2 of https://doi.org/10.6028/NIST.FIPS.197-upd1
 *
 * Round constants are defined in Table 5 of
 * https://doi.org/10.6028/NIST.FIPS.197-upd1
 */
void aes256_key_expansion_encrypt(const uint8_t *key, __m128i round_keys[15]) {
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
  // Rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]

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
}

/**
 * Expand |key| into 14 128-bit round keys, for decryption.
 *
 * Defined in Algorithm 5 of https://doi.org/10.6028/NIST.FIPS.197-upd1
 */
void aes256_key_expansion_decrypt(const uint8_t *key,
                                  __m128i round_keys[AES256_ROUNDS + 1]) {
  aes256_key_expansion_encrypt(key, round_keys);
  // Apply InverseMixColumns to keys 1 to 13
  for (int i = 1; i < AES256_ROUNDS; i++) {
    round_keys[i] = _mm_aesimc_si128(round_keys[i]);
  }
}

int aes256ecb_encrypt_with_round_keys(uint8_t *ct,
                                      const uint8_t *msg,
                                      const size_t msg_len,
                                      __m128i round_keys[AES256_ROUNDS + 1]) {
  if ((msg_len % 16) != 0) {
    return 0;
  }
  size_t num_blocks = msg_len / 16;
  __m128i *msg_blocks = (__m128i *)msg;
  __m128i *ct_blocks = (__m128i *)ct;

  for (size_t i = 0; i < num_blocks; i++) {
    __m128i state = _mm_loadu_si128(&msg_blocks[i]);
    state = _mm_xor_si128(state, round_keys[0]);
    for (int j = 1; j < AES256_ROUNDS; j++) {
      state = _mm_aesenc_si128(state, round_keys[j]);
    }
    state = _mm_aesenclast_si128(state, round_keys[AES256_ROUNDS]);
    _mm_storeu_si128(&ct_blocks[i], state);
  }
  return 1;
}

/**
 * Encrypt with AES256 in ECB mode.
 *
 * AES256.Encrypt is defined in Algorithm 1 of
 * https://doi.org/10.6028/NIST.FIPS.197-upd1
 *
 * @return one on success, zero otherwise
 */
int aes256ecb_encrypt(uint8_t *ct,
                      const uint8_t *msg,
                      const size_t msg_len,
                      const uint8_t *key) {
  __m128i round_keys[AES256_ROUNDS + 1] = {0};
  aes256_key_expansion_encrypt(key, round_keys);

  return aes256ecb_encrypt_with_round_keys(ct, msg, msg_len, round_keys);
}

/**
 * Encrypt with AES256 in ECB mode.
 *
 * AES256.Decrypt is defined in Algorithm 4 of
 * https://doi.org/10.6028/NIST.FIPS.197-upd1
 *
 * @return one on success, zero otherwise
 */
static int aes256ecb_decrypt(uint8_t *msg,
                             const uint8_t *ct,
                             const size_t ct_len,
                             const uint8_t *key) {
  if ((ct_len % 16) != 0) {
    return 0;
  }
  size_t num_blocks = ct_len / 16;
  __m128i *msg_blocks = (__m128i *)msg;
  __m128i *ct_blocks = (__m128i *)ct;

  __m128i round_keys[15];
  aes256_key_expansion_decrypt(key, round_keys);

  for (size_t i = 0; i < num_blocks; i++) {
    __m128i state = _mm_loadu_si128(&ct_blocks[i]);
    state = _mm_xor_si128(state, round_keys[AES256_ROUNDS]);
    for (int j = (AES256_ROUNDS - 1); j > 0; j--) {
      state = _mm_aesdec_si128(state, round_keys[j]);
    }
    state = _mm_aesdeclast_si128(state, round_keys[0]);
    _mm_storeu_si128(&msg_blocks[i], state);
  }
  return 1;
}

static const BlockCipher aes256ecb = {"AES256-ECB", aes256ecb_key_len,
                                      aes256ecb_block_len, aes256ecb_encrypt,
                                      aes256ecb_decrypt};

const BlockCipher *BlockCipher_aes256ecb() {
  return &aes256ecb;
}
