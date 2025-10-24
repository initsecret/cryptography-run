/*
 * Poly1305
 *
 * :copyright: (c) 2025 by OCH authors.
 * :license: Creative Commons CC0 1.0
 */

#include <assert.h>

#include <cryptography-run/axuhash.h>

#include <sodium/crypto_onetimeauth_poly1305.h>

static const uint8_t Poly1305_key_len = 32;
static const uint8_t Poly1305_digest_len = 16;

typedef crypto_onetimeauth_poly1305_state Poly1305Key;

/* ------------------------------------------------------------------------- */
/* AxuHash interface for Poly1305                                             */

// WARNING: THIS IS NOT SECURE: ONLY FOR TESTING

static int Poly1305_init(AxuHashKey *axu_key,
                         const uint8_t *key,
                         size_t key_len,
                         size_t digest_len) {
  Poly1305Key *Poly1305_key = (Poly1305Key *)axu_key;
  assert(key_len == Poly1305_key_len);
  return (crypto_onetimeauth_poly1305_init(Poly1305_key, key) == 0);
}

static int Poly1305_update_and_final(const AxuHashKey *axu_key,
                                     uint8_t *digest,
                                     size_t digest_len,
                                     const uint8_t *in,
                                     size_t in_len) {
  Poly1305Key *Poly1305_key = (Poly1305Key *)axu_key;
  assert(digest_len == Poly1305_digest_len);
  int ret = 0;
  ret |= crypto_onetimeauth_poly1305_update(Poly1305_key, in, in_len);
  ret |= crypto_onetimeauth_poly1305_final(Poly1305_key, digest);
  return (ret == 0);
}

static const AxuHash Poly1305 = {"Poly1305", Poly1305_key_len,
                                 Poly1305_digest_len, Poly1305_init,
                                 Poly1305_update_and_final};

const AxuHash *AxuHash_Poly1305() {
  return &Poly1305;
}
