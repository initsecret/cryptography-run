#ifndef CR_INTERNAL_H
#define CR_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cryptography-run/base.h>

#if defined(__cplusplus)
extern "C" {
#endif

// FIXME: support ARM
#ifdef __x86_64__

// static __m128i load128(const uint8_t *in) {
//   return _mm_loadu_si128((const __m128i *)in);
// }
// static void store128(uint8_t *out, __m128i x) {
//   _mm_storeu_si128((__m128i *)out, x);
// }
// static __m128i xor128(__m128i a, __m128i b) {
//   return _mm_xor_si128(a, b);
// }
// static __m128i zero128() {
//   return _mm_setzero_si128();
// }

// static __m256i load256(const uint8_t *in) {
//   return _mm256_loadu_si256((const __m256i *)in);
// }
// static void store256(uint8_t *out, __m256i x) {
//   _mm256_storeu_si256((__m256i *)out, x);
// }
// static __m256i xor256(const __m256i a, const __m256i b) {
//   return _mm256_xor_si256(a, b);
// }
// static __m256i zero256() {
//   return _mm256_setzero_si256();
// }

// /**
//  * out = xor(a,b) where a & b are 128-bit buffers.
//  */
// static void xor128buf(uint8_t *out, const uint8_t *a, const uint8_t *b) {
//   __m128i a0 = load128(a);
//   __m128i b0 = load128(b);
//   __m128i out0 = xor128(a0, b0);
//   store128(out, out0);
// }

// /**
//  * out = xor(a,b) where a & b are 256-bit buffers.
//  */
// static void xor256buf(uint8_t *out, const uint8_t *a, const uint8_t *b) {
//   xor128buf(out, a, b);
//   xor128buf(out + 16, a + 16, b + 16);
// }

#endif  // __x86_64__

#ifdef __cplusplus
}
#endif

#endif  // CR_INTERNAL_H