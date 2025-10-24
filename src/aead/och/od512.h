/*
 * Overwrite Duplex based on a 512-bit permutation
 *
 * :copyright: (c) 2025 by OCH authors.
 * :license: Creative Commons CC0 1.0
 */

#ifndef CR_OD512_H
#define CR_OD512_H

#include <assert.h>
#include <cryptography-run/hash.h>

#if defined(__cplusplus)
extern "C" {
#endif

static const uint8_t OD512_rate = 32;
static const uint8_t OD512_capacity = 32;

static const uint8_t OD512_permwidth = OD512_rate + OD512_capacity;
static const uint8_t OD512_key_len = OD512_capacity;
static const uint8_t OD512_digest_len = OD512_capacity;

typedef u256_t OD512Cap;
typedef u256_t OD512Rate;

/**
 * API for Duplexing a 256-bit chunk with a 512-bit Overwrite Duplex.
 * |rate| and |cap| are overwritten with new rate and cap
 */
typedef void (*OD512_DuplexChunk)(OD512Rate *rate, OD512Cap *cap);

typedef struct {
  OD512Cap capacity;
  OD512Rate rate;
  uint8_t rate_fill;
  bool finalized;
  OD512_DuplexChunk duplex_chunk;
} OD512_ctx;

/**
 * eats |in_bytes| of |in|, updates |cap|, and writes the output to |digest|.
 * @return true on success and false otherwise.
 */
static bool OD512_Duplexing(OD512_DuplexChunk duplex_chunk,
                            OD512Cap *cap,
                            OD512Rate *digest,
                            const uint8_t *in,
                            size_t in_len) {
  // first eat 32-byte chunks
  int in_idx = 0;
  for (; (in_idx + 32) <= in_len; in_idx += 32) {
    *digest = load256(in + in_idx);
    duplex_chunk(digest, cap);
  }
  // now eat excess, and handle empty inputs
  if ((in_idx < in_len) || (in_len == 0)) {
    assert((in_len - in_idx) < 32);
    uint8_t excess[32] = {0};
    int excess_idx = 0;
    for (; excess_idx < (in_len - in_idx); excess_idx += 1) {
      excess[excess_idx] = in[in_idx + excess_idx];
    }
    assert(in_len == (in_idx + excess_idx));
    assert(excess_idx < 32);
    excess[excess_idx] = 0xff;
    *digest = load256(excess);
    (*duplex_chunk)(digest, cap);
  }
  return true;
}

#ifdef __cplusplus
}
#endif

#endif  // CR_OD512_H
