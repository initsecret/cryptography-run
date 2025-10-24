#ifndef CR_CIPHER_H
#define CR_CIPHER_H

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

// FIXME: support ARM
#ifdef __x86_64__
#include <wmmintrin.h>

#define CIPHER_MAX_KEY_LENGTH 32  // Rijndael256

// CipherState represents the internal state of a block or stream cipher.
// Aligned to 32 byte boundary.
typedef struct {
  alignas(32) uint8_t opaque[128];
} CipherState;

// BlockCipher represents a block cipher in ECB mode.
typedef struct {
  /** name of scheme */
  char name[100];
  /** length of key in bytes */
  uint8_t key_len;
  /** length of a block in bytes */
  uint8_t block_len;

  // /**
  //  * Initalizes CipherState |cipher_ctx| with |key|.
  //  *
  //  * |key| MUST be |Cipher.key_len| bytes long.
  //  *
  //  * @return one on success and zero otherwise.
  //  */
  // int (*init)(CipherState *cipher_ctx, const uint8_t *key);

  /**
   * Encrypts |msg| and writes the ciphertext to |ct|.
   *
   * At most |msg_len| bytes are written to |ct|.
   *
   * |cipher_ctx| MUST be initialized.
   *
   * |msg_len| MUST be a multiple of |Cipher.block_len|.
   *
   * |msg| and |ct| may be the same buffer.
   *
   * @return one on success and zero otherwise.
   */
  int (*encrypt)(uint8_t *ct,
                 const uint8_t *msg,
                 size_t msg_len,
                 const uint8_t *key);

  /**
   * Decrypts |ct| and writes the plaintext to |msg|.
   *
   * At most |msg_len| bytes are written to |ct|.
   *
   * |cipher_ctx| MUST be initialized.
   *
   * |msg_len| MUST be a multiple of |Cipher.block_len|.
   *
   * |msg| and |ct| may be the same buffer.
   *
   * @return one on success and zero otherwise.
   */
  int (*decrypt)(uint8_t *msg,
                 const uint8_t *ct,
                 size_t ct_len,
                 const uint8_t *key);
} BlockCipher;

const BlockCipher *BlockCipher_aes256ecb();
const BlockCipher *BlockCipher_rijndael256ecb();

// FIXME: add properly to API

void aes256_key_expansion_encrypt(const uint8_t *key, __m128i round_keys[15]);
int aes256ecb_encrypt_with_round_keys(uint8_t *ct,
                                      const uint8_t *msg,
                                      const size_t msg_len,
                                      __m128i round_keys[15]);

#endif  // __x86_64__

#ifdef __cplusplus
}
#endif

#endif  // CR_CIPHER_H