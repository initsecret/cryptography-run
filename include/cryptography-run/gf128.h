/*
 * GF(2^128)
 *
 * TODO: under construction
 *
 * :copyright: (c) 2025 by OCH authors.
 * :license: Creative Commons CC0 1.0
 */

#ifndef CR_GF128_H
#define CR_GF128_H

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#include "base.h"

#if defined(__cplusplus)
extern "C" {
#endif

/**
 * GF(2^128) - Polyval field
 *
 * modulus: f(x) = x^128 + x^127 + x^126 + x^121 + 1
 *
 * see https://www.rfc-editor.org/rfc/rfc8452.html and
 * https://github.com/agl/gcmsiv/blob/master/gcmsiv.go
 */

/**
 * computes
 *   dot(a,b) = a * b * x^{-128} mod x^128 + x^127 + x^126 + x^121 + 1
 * and stores the result to a.
 *
 * dot is defined in https://www.rfc-editor.org/rfc/rfc8452.html#section-3
 */
void gf128_dot(u128_t *a, const u128_t *b);

// // Use 256 bits to represent an element of GF(2^128). The extra 128 bits are
// // useful when we multiply.
// typedef u256_t gf128_t;
//
// static inline u128_t gf128_add(const u128_t a, const u128_t b) {
//   u128_t ret = a;
//   return ret;
// }
//
// static inline u128_t gf128_mul(const u128_t a, const u128_t b) {
//   u128_t ret = a;
//   return ret;
// }
//
// static inline u128_t gf128_dot(const u128_t a, const u128_t b) {
//   u128_t ret = a;
//   return ret;
// }

#ifdef __cplusplus
}
#endif

#endif  // CR_GF128_H
