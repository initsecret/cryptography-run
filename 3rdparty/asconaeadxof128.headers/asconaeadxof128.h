/*
 * Extracted headers for libcrypto_hash_asconaeadxof128_opt64.a when built with
 * DASCON_INLINE_MODE=0
 *
 * adapted from ascon.h
 */

#ifndef _asconaeadxof128_h_
#define _asconaeadxof128_h_

#include <stdint.h>

// From api.h
#define CRYPTO_VERSION "1.3.0"
#define CRYPTO_BYTES 64
#define ASCON_HASH_BYTES 0 /* XOF */
#define ASCON_HASH_ROUNDS 12

#define CRYPTO_KEYBYTES 16
#define CRYPTO_NSECBYTES 0
#define CRYPTO_NPUBBYTES 16
#define CRYPTO_ABYTES 16
#define CRYPTO_NOOVERLAP 1
#define ASCON_AEAD_RATE 16

typedef union {
  uint64_t x[5];
  uint32_t w[5][2];
  uint8_t b[5][8];
} ascon_state_t;

#define ASCON_KEYWORDS (CRYPTO_KEYBYTES + 7) / 8

typedef union {
  uint64_t x[ASCON_KEYWORDS];
  uint32_t w[ASCON_KEYWORDS][2];
  uint8_t b[ASCON_KEYWORDS][8];
} ascon_key_t;

void ascon_loadkey(ascon_key_t *key, const uint8_t *k);
void ascon_initaead(ascon_state_t *s,
                    const ascon_key_t *key,
                    const uint8_t *npub);
void ascon_adata(ascon_state_t *s, const uint8_t *ad, uint64_t adlen);
void ascon_encrypt(ascon_state_t *s,
                   uint8_t *c,
                   const uint8_t *m,
                   uint64_t mlen);
void ascon_decrypt(ascon_state_t *s,
                   uint8_t *m,
                   const uint8_t *c,
                   uint64_t clen);
void ascon_final(ascon_state_t *s, const ascon_key_t *k);
void ascon_gettag(ascon_state_t* s, uint8_t* t);
int ascon_verify(ascon_state_t* s, const uint8_t* t);

int ascon_aead_encrypt(uint8_t *t,
                       uint8_t *c,
                       const uint8_t *m,
                       uint64_t mlen,
                       const uint8_t *ad,
                       uint64_t adlen,
                       const uint8_t *npub,
                       const uint8_t *k);
int ascon_aead_decrypt(uint8_t *m,
                       const uint8_t *t,
                       const uint8_t *c,
                       uint64_t clen,
                       const uint8_t *ad,
                       uint64_t adlen,
                       const uint8_t *npub,
                       const uint8_t *k);

void ascon_inithash(ascon_state_t *s);
void ascon_absorb(ascon_state_t *s, const uint8_t *in, uint64_t inlen);
void ascon_squeeze(ascon_state_t *s, uint8_t *out, uint64_t outlen);

int ascon_xof(uint8_t *out, uint64_t outlen, const uint8_t *in, uint64_t inlen);

#endif  // _asconaeadxof128_h_
