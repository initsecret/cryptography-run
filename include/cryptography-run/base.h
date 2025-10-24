#ifndef CR_BASE_H
#define CR_BASE_H

#include <assert.h>
#include <stdalign.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "_cr_types.h"

#ifdef __APPLE__
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#define htole64(x) OSSwapHostToLittleInt64(x)
#define le64toh(x) OSSwapLittleToHostInt64(x)
#else
#include <endian.h>
#endif

#if defined(__SSSE3__) || defined(__ARM_NEON)
#define CR_HAS_AREION
#endif

#if defined(__cplusplus)
extern "C" {
#endif

#define ntz(x) __builtin_ctz(x)

static void zeroize(void *dst, size_t count) {
  // FIXME: - use memset_explict on C23
  //        - use memzero_explicit on supported linux
  //        - ...
  memset(dst, 0x00, count);
}

/**
 * @return one if |a| and |b| are equal for the first |len| bytes, and zero
 * otherwise.
 * FIXME: replace this with equal_bytes
 */
static int constant_time_compare(const uint8_t *a,
                                 const uint8_t *b,
                                 size_t len) {
  uint8_t ret = 0;
  for (size_t i = 0; i < len; i++) {
    ret |= a[i] ^ b[i];
  }
  return !ret;
}

/**
 * @return true if |a| and |b| are equal for the first |len| bytes, and false
 * otherwise.
 */
static bool equal_bytes(const uint8_t *a, const uint8_t *b, size_t len) {
  uint8_t diff = 0;
  for (size_t i = 0; i < len; i++) {
    // iff a[i] and b[i] are equal, then a[i] ^ b[i] = 0x00.
    diff |= a[i] ^ b[i];
  }
  // if a[i] ≠ b[i] for any i, then diff != 0,
  // and diff == 0 iff a[i] = b[i] for all i.
  return (diff == 0);
}

/**
 * Fills |buf| with |buf_len| bytes of randomness.
 *
 * @return one on success and zero otherwise.
 */
#ifdef __MACH__
// getentropy returns 0 on success
#define RANDOM_BYTES(buf, buf_len) (getentropy(buf, buf_len) == 0)
#else
// getrandom returns -1 on failure
#define RANDOM_BYTES(buf, buf_len) \
  (getrandom(buf, buf_len, GRND_NONBLOCK) != -1)
#endif

#ifdef __cplusplus
}
#endif

#endif  // CR_BASE_H
