#ifndef CR_AXUHASH_H
#define CR_AXUHASH_H

#include <cryptography-run/base.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define AXU_HASH_MAX_KEY_LENGTH 32     // X2Polyval
#define AXU_HASH_MAX_DIGEST_LENGTH 32  // X2Polyval

#define AXU_HASH_MAX_KEY_SIZE 256   // X2Polyval
#define AXU_HASH_MAX_STATE_SIZE 32  // X2Polyval

/**
 * AxuHashKey represents a key with precomputation.
 */
typedef struct {
  alignas(32) uint8_t opaque[AXU_HASH_MAX_KEY_SIZE];
} AxuHashKey;

/**
 * AxuHashState represents the internal state of a Hash.
 * NOTE: currently unused, since we don't have an incremental API.
 */
typedef struct {
  alignas(8) uint8_t opaque[AXU_HASH_MAX_STATE_SIZE];
} AxuHashState;

/**
 * AxuHash represents an AXU hash scheme.
 */
typedef struct {
  /** name of scheme */
  char name[100];
  /** length of key in bytes */
  uint8_t key_len;
  /** length of digest in bytes */
  uint8_t digest_len;

  int (*init)(AxuHashKey *axu_key,
              const uint8_t *key,
              size_t key_len,
              size_t digest_len);
  int (*update_and_final)(const AxuHashKey *axu_key,
                          uint8_t *digest,
                          size_t digest_len,
                          const uint8_t *in,
                          size_t in_len);
} AxuHash;

const AxuHash *AxuHash_Polyval();
const AxuHash *AxuHash_X2Polyval();

const AxuHash *AxuHash_Poly1305();

#ifdef __cplusplus
}
#endif

#endif  // CR_AXUHASH_H
