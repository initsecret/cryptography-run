/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com). */
/* ====================================================================
 * Copyright (c) 1999-2007 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ==================================================================== */

/* Copyright (c) 2024, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. */

/* ------------------------------------------------------------------------- */
/* Hash interface for SHA256                                                 */

#include <assert.h>
#include <string.h>

#include "../../internal.h"

#include <cryptography-run/hash.h>

static inline uint32_t CRYPTO_bswap4(uint32_t x) {
  return __builtin_bswap32(x);
}

static inline void CRYPTO_store_u32_be(void *out, uint32_t v) {
  v = CRYPTO_bswap4(v);
  memcpy(out, &v, sizeof(v));
}

static inline void CRYPTO_store_u32_le(void *out, uint32_t v) {
  memcpy(out, &v, sizeof(v));
}

// SHA256_CBLOCK is the block size of SHA-256.
#define BCM_SHA256_CBLOCK 64

// BCM_SHA256_DIGEST_LENGTH is the length of a SHA-256 digest.
#define BCM_SHA256_DIGEST_LENGTH 32

// SHA256_CTX
struct sha256_state_st {
  uint32_t h[8];
  uint32_t Nl, Nh;
  uint8_t data[BCM_SHA256_CBLOCK];
  unsigned num, md_len;
};
typedef struct sha256_state_st SHA256_CTX;

// Implemented in assembly
void sha256_block_data_order_hw(uint32_t state[8],
                                const uint8_t *data,
                                size_t num);
void sha256_block_data_order_nohw(uint32_t state[8],
                                  const uint8_t *data,
                                  size_t num);
void sha256_block_data_order_ssse3(uint32_t state[8],
                                   const uint8_t *data,
                                   size_t num);
void sha256_block_data_order_avx(uint32_t state[8],
                                 const uint8_t *data,
                                 size_t num);

void sha256_block_data_order(uint32_t state[8],
                             const uint8_t *data,
                             size_t num) {
  sha256_block_data_order_hw(state, data, num);
  return;
}

// BCM_sha256_transform_blocks is a low-level function that takes |num_blocks| *
// |BCM_SHA256_CBLOCK| bytes of data and performs SHA-256 transforms on it to
// update |state|.
static void BCM_sha256_transform_blocks(uint32_t state[8],
                                        const uint8_t *data,
                                        size_t num_blocks) {
  sha256_block_data_order(state, data, num_blocks);
  return;
}

// BCM_sha256_init initialises |sha|.
static void BCM_sha256_init(SHA256_CTX *sha) {
  zeroize(sha, sizeof(SHA256_CTX));
  sha->h[0] = 0x6a09e667UL;
  sha->h[1] = 0xbb67ae85UL;
  sha->h[2] = 0x3c6ef372UL;
  sha->h[3] = 0xa54ff53aUL;
  sha->h[4] = 0x510e527fUL;
  sha->h[5] = 0x9b05688cUL;
  sha->h[6] = 0x1f83d9abUL;
  sha->h[7] = 0x5be0cd19UL;
  sha->md_len = BCM_SHA256_DIGEST_LENGTH;
  return;
}

// BCM_sha256_transform is a low-level function that performs a single, SHA-256
// block transformation using the state from |sha| and |BCM_SHA256_CBLOCK| bytes
// from |block|.
static void BCM_sha256_transform(SHA256_CTX *c,
                                 const uint8_t data[BCM_SHA256_CBLOCK]) {
  sha256_block_data_order(c->h, data, 1);
  return;
}

// This is a generic 32-bit "collector" for message digest algorithms. It
// collects input character stream into chunks of 32-bit values and invokes the
// block function that performs the actual hash calculations.
//
// To make use of this mechanism, the hash context should be defined with the
// following parameters.
//
//     typedef struct <name>_state_st {
//       uint32_t h[<chaining length> / sizeof(uint32_t)];
//       uint32_t Nl, Nh;
//       uint8_t data[<block size>];
//       unsigned num;
//       ...
//     } <NAME>_CTX;
//
// <chaining length> is the output length of the hash in bytes, before
// any truncation (e.g. 64 for SHA-224 and SHA-256, 128 for SHA-384 and
// SHA-512).
//
// |h| is the hash state and is updated by a function of type
// |crypto_md32_block_func|. |data| is the partial unprocessed block and has
// |num| bytes. |Nl| and |Nh| maintain the number of bits processed so far.

// A crypto_md32_block_func should incorporate |num_blocks| of input from |data|
// into |state|. It is assumed the caller has sized |state| and |data| for the
// hash function.
typedef void (*crypto_md32_block_func)(uint32_t *state,
                                       const uint8_t *data,
                                       size_t num_blocks);

// crypto_md32_update adds |len| bytes from |in| to the digest. |data| must be a
// buffer of length |block_size| with the first |*num| bytes containing a
// partial block. This function combines the partial block with |in| and
// incorporates any complete blocks into the digest state |h|. It then updates
// |data| and |*num| with the new partial block and updates |*Nh| and |*Nl| with
// the data consumed.
static inline void crypto_md32_update(crypto_md32_block_func block_func,
                                      uint32_t *h,
                                      uint8_t *data,
                                      size_t block_size,
                                      unsigned *num,
                                      uint32_t *Nh,
                                      uint32_t *Nl,
                                      const uint8_t *in,
                                      size_t len) {
  if (len == 0) {
    return;
  }

  uint32_t l = *Nl + (((uint32_t)len) << 3);
  if (l < *Nl) {
    // Handle carries.
    (*Nh)++;
  }
  *Nh += (uint32_t)(len >> 29);
  *Nl = l;

  size_t n = *num;
  if (n != 0) {
    if (len >= block_size || len + n >= block_size) {
      memcpy(data + n, in, block_size - n);
      block_func(h, data, 1);
      n = block_size - n;
      in += n;
      len -= n;
      *num = 0;
      // Keep |data| zeroed when unused.
      memset(data, 0, block_size);
    } else {
      memcpy(data + n, in, len);
      *num += (unsigned)len;
      return;
    }
  }

  n = len / block_size;
  if (n > 0) {
    block_func(h, in, n);
    n *= block_size;
    in += n;
    len -= n;
  }

  if (len != 0) {
    *num = (unsigned)len;
    memcpy(data, in, len);
  }
}

// crypto_md32_final incorporates the partial block and trailing length into the
// digest state |h|. The trailing length is encoded in little-endian if
// |is_big_endian| is zero and big-endian otherwise. |data| must be a buffer of
// length |block_size| with the first |*num| bytes containing a partial block.
// |Nh| and |Nl| contain the total number of bits processed. On return, this
// function clears the partial block in |data| and
// |*num|.
//
// This function does not serialize |h| into a final digest. This is the
// responsibility of the caller.
static inline void crypto_md32_final(crypto_md32_block_func block_func,
                                     uint32_t *h,
                                     uint8_t *data,
                                     size_t block_size,
                                     unsigned *num,
                                     uint32_t Nh,
                                     uint32_t Nl,
                                     int is_big_endian) {
  // |data| always has room for at least one byte. A full block would have
  // been consumed.
  size_t n = *num;
  assert(n < block_size);
  data[n] = 0x80;
  n++;

  // Fill the block with zeros if there isn't room for a 64-bit length.
  if (n > block_size - 8) {
    memset(data + n, 0, block_size - n);
    n = 0;
    block_func(h, data, 1);
  }
  memset(data + n, 0, block_size - 8 - n);

  // Append a 64-bit length to the block and process it.
  if (is_big_endian) {
    CRYPTO_store_u32_be(data + block_size - 8, Nh);
    CRYPTO_store_u32_be(data + block_size - 4, Nl);
  } else {
    CRYPTO_store_u32_le(data + block_size - 8, Nl);
    CRYPTO_store_u32_le(data + block_size - 4, Nh);
  }
  block_func(h, data, 1);
  *num = 0;
  memset(data, 0, block_size);
}

// BCM_sha256_update adds |len| bytes from |data| to |sha|.
static void BCM_sha256_update(SHA256_CTX *c, const void *data, size_t len) {
  crypto_md32_update(&sha256_block_data_order, c->h, c->data, BCM_SHA256_CBLOCK,
                     &c->num, &c->Nh, &c->Nl, data, len);
  return;
}

static void sha256_final_impl(uint8_t *out, size_t md_len, SHA256_CTX *c) {
  crypto_md32_final(&sha256_block_data_order, c->h, c->data, BCM_SHA256_CBLOCK,
                    &c->num, c->Nh, c->Nl, /*is_big_endian=*/1);

  assert(md_len <= BCM_SHA256_DIGEST_LENGTH);

  assert(md_len % 4 == 0);
  const size_t out_words = md_len / 4;
  for (size_t i = 0; i < out_words; i++) {
    CRYPTO_store_u32_be(out, c->h[i]);
    out += 4;
  }
}

// BCM_sha256_final adds the final padding to |sha| and writes the resulting
// digest to |out|, which must have at least |BCM_SHA256_DIGEST_LENGTH| bytes of
// space. It aborts on programmer error.
static void BCM_sha256_final(uint8_t out[BCM_SHA256_DIGEST_LENGTH],
                             SHA256_CTX *c) {
  // Ideally we would assert |sha->md_len| is |BCM_SHA256_DIGEST_LENGTH| to
  // match the size hint, but calling code often pairs |SHA224_Init| with
  // |SHA256_Final| and expects |sha->md_len| to carry the size over.
  //
  // TODO(davidben): Add an assert and fix code to match them up.
  sha256_final_impl(out, c->md_len, c);
  return;
}

/* ------------------------------------------------------------------------- */

// SHA256_DIGEST_LENGTH is the length of a SHA-256 digest.
#define SHA256_DIGEST_LENGTH 32

// SHA256_Init initialises |sha| and returns 1.
int SHA256_Init(SHA256_CTX *sha) {
  BCM_sha256_init(sha);
  return 1;
}

// SHA256_Update adds |len| bytes from |data| to |sha| and returns 1.
int SHA256_Update(SHA256_CTX *sha, const void *data, size_t len) {
  BCM_sha256_update(sha, data, len);
  return 1;
}

// SHA256_Final adds the final padding to |sha| and writes the resulting digest
// to |out|, which must have at least |SHA256_DIGEST_LENGTH| bytes of space. It
// returns one on success and zero on programmer error.
int SHA256_Final(uint8_t out[SHA256_DIGEST_LENGTH], SHA256_CTX *sha) {
  // TODO(bbe): This overflow check one of the few places a low-level hash
  // 'final' function can fail. SHA-512 does not have a corresponding check.
  // The BCM function is infallible and will abort if this is done incorrectly.
  // we should verify nothing crashes with this removed and eliminate the 0
  // return.
  if (sha->md_len > SHA256_DIGEST_LENGTH) {
    return 0;
  }
  BCM_sha256_final(out, sha);
  return 1;
}

// SHA256 writes the digest of |len| bytes from |data| to |out| and returns
// one. There must be at least |SHA256_DIGEST_LENGTH| bytes of space in
// |out|.
int SHA256(const uint8_t *data, size_t len, uint8_t out[SHA256_DIGEST_LENGTH]) {
  SHA256_CTX ctx;
  BCM_sha256_init(&ctx);
  BCM_sha256_update(&ctx, data, len);
  BCM_sha256_final(out, &ctx);
  zeroize(&ctx, sizeof(ctx));
  return 1;
}

/* ------------------------------------------------------------------------- */

static const uint8_t hash_sha256_key_len = 32;
static const uint8_t hash_sha256_digest_len = 32;

typedef SHA256_CTX hash_sha256_ctx;

static int hash_sha256_hash(uint8_t *digest,
                            size_t digest_len,
                            const uint8_t *msg,
                            size_t msg_len) {
  assert(digest_len == hash_sha256_digest_len);
  return SHA256(msg, msg_len, digest);
}

static int hash_sha256_keyed_hash(const uint8_t *key,
                                  size_t key_len,
                                  uint8_t *digest,
                                  size_t digest_len,
                                  const uint8_t *msg,
                                  size_t msg_len) {
  assert(digest_len == hash_sha256_digest_len);
  // FIXME: this is vulnerable to length-extension attacks
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, key, key_len);
  SHA256_Update(&ctx, msg, msg_len);
  SHA256_Final(digest, &ctx);
  zeroize(&ctx, sizeof(ctx));
  return 1;
}

static int hash_sha256_init(HashState *hash_ctx,
                            const uint8_t *key,
                            size_t key_len,
                            size_t digest_length) {
  hash_sha256_ctx *ctx = (hash_sha256_ctx *)hash_ctx;
  assert(digest_length == hash_sha256_digest_len);
  // FIXME: this is vulnerable to length-extension attacks
  SHA256_Init(ctx);
  if (key_len > 0) {
    SHA256_Update(ctx, key, key_len);
  }
  return 1;
}

static int hash_sha256_update(HashState *hash_ctx,
                              const uint8_t *in,
                              size_t in_len) {
  hash_sha256_ctx *ctx = (hash_sha256_ctx *)hash_ctx;
  return SHA256_Update(ctx, in, in_len);
}

static int hash_sha256_final(HashState *hash_ctx,
                             uint8_t *digest,
                             size_t digest_len) {
  assert(digest_len == hash_sha256_digest_len);
  hash_sha256_ctx *ctx = (hash_sha256_ctx *)hash_ctx;
  return SHA256_Final(digest, ctx);
}

static const Hash hash_sha256 = {
    "SHA256",           hash_sha256_key_len,    hash_sha256_digest_len,
    hash_sha256_hash,   hash_sha256_keyed_hash, hash_sha256_init,
    hash_sha256_update, hash_sha256_final};

const Hash *Hash_sha256() {
  return &hash_sha256;
}
