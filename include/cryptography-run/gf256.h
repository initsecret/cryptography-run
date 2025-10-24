/*
 * GF(2^256)
 *
 * :copyright: (c) 2025 by OCH authors.
 * :license: Creative Commons CC0 1.0
 */

#ifndef CR_GF256_H
#define CR_GF256_H

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#include "base.h"

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * Double in GF(2^256)
 *
 * modulus: f(x) = x^256 + x^10 + x^5 + x^2 + 1
 * mask = f(2) mod 2^256 = 2^10 + 2^5 + 2^2 + 1 = 1061
 *
 * double(a) = (a << 1) ^ ( 1061 & -( a >> 255 ) )
 *
 * Based on 128-bit double_block in Ted Krovetz's OCB3 implementation:
 * https://www.cs.ucdavis.edu/~rogaway/ocb/news/ See also
 * https://crypto.stackexchange.com/a/63273
 */
static inline u256_t gf256_double(const u256_t in) {
  u256_t ret = in;

  // convert to big-endian u64s
  // on little-endian systems, htobe64 = bswap64
  for (int i = 0; i < 4; i += 1) {
    ret.u64[i] = htobe64(ret.u64[i]);
  }

  uint64_t mask = 1061;
  uint64_t tmp = ret.u64[0] >> 63;

  ret.u64[0] = (ret.u64[0] << 1) ^ (ret.u64[1] >> 63);
  ret.u64[1] = (ret.u64[1] << 1) ^ (ret.u64[2] >> 63);
  ret.u64[2] = (ret.u64[2] << 1) ^ (ret.u64[3] >> 63);
  ret.u64[3] = (ret.u64[3] << 1) ^ (mask & -tmp);

  // convert back to hardware u64s
  // on little-endian systems, be64toh = bswap64
  for (int i = 0; i < 4; i += 1) {
    ret.u64[i] = be64toh(ret.u64[i]);
  }
  return ret;
}

#ifdef __cplusplus
}
#endif

#endif  // CR_GF256_H
