
#ifndef _CR_TYPES_H
#define _CR_TYPES_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define CR_USE_HW_IF_AVAILABLE 1

#if defined(__SSSE3__)
#define CR_INTEL_HW CR_USE_HW_IF_AVAILABLE
#include <emmintrin.h>  // SSE2
#include <immintrin.h>  // AVX
#include <wmmintrin.h>  // AES and PCLMUL
#include <xmmintrin.h>  // SSE
#elif defined(__ARM_NEON)
#define CR_ARM_HW CR_USE_HW_IF_AVAILABLE
#include <arm_neon.h>
#endif

#if defined(__cplusplus)
extern "C" {
#endif

// bytes are bytes
// 32words are 32-bit words, doublewords in intel speak
// 64words are 64-bit words, quadwords in intel speak

#define CR_U128_BYTES 16
#define CR_U128_32WORDS (CR_U128_BYTES / 4)
#define CR_U128_64WORDS (CR_U128_BYTES / 8)

#define CR_U256_BYTES 32
#define CR_U256_32WORDS (CR_U256_BYTES / 4)
#define CR_U256_64WORDS (CR_U256_BYTES / 8)
#define CR_U256_128WORDS (CR_U256_BYTES / 16)

#define CR_U512_BYTES 64
#define CR_U512_32WORDS (CR_U512_BYTES / 4)
#define CR_U512_64WORDS (CR_U512_BYTES / 8)
#define CR_U512_128WORDS (CR_U512_BYTES / 16)
#define CR_U512_256WORDS (CR_U512_BYTES / 32)

typedef union {
  uint8_t u8[CR_U128_BYTES];
  uint32_t u32[CR_U128_32WORDS];
  uint64_t u64[CR_U128_64WORDS];
  struct {
    uint64_t hi, lo;
  };
#if CR_INTEL_HW
  __m128i intel128;
  __m128i native128;
#elif CR_ARM_HW
  uint8x16_t arm128;
  uint8x16_t native128;
#endif
} u128_t;

typedef union {
  uint8_t u8[CR_U256_BYTES];
  uint32_t u32[CR_U256_32WORDS];
  uint64_t u64[CR_U256_64WORDS];
  u128_t u128[CR_U256_128WORDS];
#if CR_INTEL_HW
  __m128i intel128[2];
  __m128i native128[2];
  __m256i intel256;
#elif CR_ARM_HW
  uint8x16_t arm128[2];
  uint8x16_t native128[2];
#endif
} u256_t;

typedef union {
  uint8_t u8[CR_U512_BYTES];
  uint32_t u32[CR_U512_32WORDS];
  uint64_t u64[CR_U512_64WORDS];
  u128_t u128[CR_U512_128WORDS];
  u256_t u256[CR_U512_256WORDS];
#if CR_INTEL_HW
  __m128i intel128[4];
  __m128i native128[4];
  __m256i intel256[2];
#elif CR_ARM_HW
  uint8x16_t arm128[4];
  uint8x16_t native128[4];
#endif
} u512_t;

/**
 * @return true if |a| and |b| are equal, and false otherwise.
 */
static bool equal128(const u128_t a, const u128_t b) {
#if CR_INTEL_HW
  // _mm_cmpeq_epi8 does a byte-wise compare. for each byte of |a| and |b|: if
  // they equal it sets the corresponding byte in the return value to 0xff, and
  // 0x00 if not. _mm_cmpeq_epi8 returns the most significant bit of each byte.
  // So, if |a| and |b| are equal, then we get all-ones.
  return (_mm_movemask_epi8(_mm_cmpeq_epi8(a.intel128, b.intel128)) ==
          0b1111111111111111);
#else
  uint32_t diff = 0;
  for (int i = 0; i < CR_U128_32WORDS; i++) {
    diff |= a.u32[i] ^ b.u32[i];
  }
  return (diff == 0);
#endif
}

/**
 * @return true if |a| and |b| are equal, and false otherwise.
 * TODO: do this with intrinsics?
 */
static bool equal256(const u256_t a, const u256_t b) {
  uint32_t diff = 0;
  for (int i = 0; i < CR_U256_32WORDS; i++) {
    diff |= a.u32[i] ^ b.u32[i];
  }
  return (diff == 0);
}

static u128_t copy128(const u128_t a) {
  u128_t ret;
#if CR_INTEL_HW
  ret.intel128 = a.intel128;
#elif CR_ARM_HW
  ret.arm128 = a.arm128;
#else
  for (int i = 0; i < CR_U128_32WORDS; i++) {
    ret.u32[i] = a.u32[i];
  }
#endif
  return ret;
}

static u256_t copy256(const u256_t a) {
  u256_t ret;
#if CR_INTEL_HW
  ret.intel256 = a.intel256;
#elif CR_ARM_HW
  ret.arm128[0] = a.arm128[0];
  ret.arm128[1] = a.arm128[1];
#else
  for (int i = 0; i < CR_U256_32WORDS; i++) {
    ret.u32[i] = a.u32[i];
  }
#endif
  return ret;
}

static u128_t xor128(const u128_t a, const u128_t b) {
  u128_t ret;
#if CR_INTEL_HW
  ret.intel128 = _mm_xor_si128(a.intel128, b.intel128);
#elif CR_ARM_HW
  ret.arm128 = veorq_u8(a.arm128, b.arm128);
#else
  for (int i = 0; i < CR_U128_32WORDS; i++) {
    ret.u32[i] = a.u32[i] ^ b.u32[i];
  }
#endif
  return ret;
}

static inline u256_t xor256(const u256_t a, const u256_t b) {
  u256_t ret;
#if CR_INTEL_HW
  ret.intel256 = _mm256_xor_si256(a.intel256, b.intel256);
#elif CR_ARM_HW
  ret.arm128[0] = veorq_u8(a.arm128[0], b.arm128[0]);
  ret.arm128[1] = veorq_u8(a.arm128[1], b.arm128[1]);
#else
  for (int i = 0; i < CR_U256_32WORDS; i++) {
    ret.u32[i] = a.u32[i] ^ b.u32[i];
  }
#endif
  return ret;
}

static u128_t zero128() {
  u128_t ret;
#if CR_INTEL_HW
  ret.intel128 = _mm_setzero_si128();
#elif CR_ARM_HW
  ret.arm128 = vdupq_n_u8(0);
#else
  for (int i = 0; i < CR_U128_32WORDS; i++) {
    ret.u32[i] = 0;
  }
#endif
  return ret;
}

static u256_t zero256() {
  u256_t ret;
#if CR_INTEL_HW
  ret.intel256 = _mm256_setzero_si256();
#elif CR_ARM_HW
  ret.arm128[0] = vdupq_n_u8(0);
  ret.arm128[1] = vdupq_n_u8(0);
#else
  for (int i = 0; i < CR_U256_32WORDS; i++) {
    ret.u32[i] = 0;
  }
#endif
  return ret;
}

static u256_t shiftleft256(const u256_t a, uint8_t value) {
  u256_t ret = zero256();
#if CR_INTEL_HW
  ret.intel256 = _mm256_slli_epi64(a.intel256, value);
#else
  if (value == 0) {
    ret.u64[0] = a.u64[0];
    ret.u64[1] = a.u64[1];
    ret.u64[2] = a.u64[2];
    ret.u64[3] = a.u64[3];
  } else {
    ret.u64[0] = (a.u64[0] << value) | (a.u64[1] >> (64 - value));
    ret.u64[1] = (a.u64[1] << value) | (a.u64[2] >> (64 - value));
    ret.u64[2] = (a.u64[2] << value) | (a.u64[3] >> (64 - value));
    ret.u64[3] = (a.u64[3] << value);
  }
#endif
  return ret;
}

static u128_t load128(const uint8_t *in) {
  u128_t ret;
#if CR_INTEL_HW
  ret.intel128 = _mm_loadu_si128((const __m128i *)in);
#elif CR_ARM_HW
  ret.arm128 = vld1q_u8(in);
#else
  memcpy(ret.u8, in, CR_U128_BYTES);
#endif
  return ret;
}

static u256_t load256(const uint8_t *in) {
  u256_t ret;
#if CR_INTEL_HW
  ret.intel256 = _mm256_loadu_si256((const __m256i *)in);
#elif CR_ARM_HW
  ret.arm128[0] = vld1q_u8(in);
  ret.arm128[1] = vld1q_u8(in + 16);
#else
  memcpy(ret.u8, in, CR_U256_BYTES);
#endif
  return ret;
}

static void store128(uint8_t *out, u128_t x) {
#if CR_INTEL_HW
  _mm_storeu_si128((__m128i *)out, x.intel128);
#elif CR_ARM_HW
  vst1q_u8(out, x.arm128);
#else
  memcpy(out, x.u8, CR_U128_BYTES);
#endif
}

static void store256(uint8_t *out, u256_t x) {
#if CR_INTEL_HW
  _mm256_storeu_si256((__m256i *)out, x.intel256);
#elif CR_ARM_HW
  vst1q_u8(out, x.arm128[0]);
  vst1q_u8(out + 16, x.arm128[1]);
#else
  memcpy(out, x.u8, CR_U256_BYTES);
#endif
}

#ifdef __cplusplus
}
#endif

#endif /* _CR_TYPES_H */
