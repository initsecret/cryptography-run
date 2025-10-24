#ifndef CR_HASH_H
#define CR_HASH_H

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#include <cryptography-run/base.h>

#if defined(__cplusplus)
extern "C" {
#endif

#define HASH_MAX_KEY_LENGTH 32     // Blake2b
#define HASH_MAX_DIGEST_LENGTH 64  // Blake2b

#define HASH_MAX_CTX_SIZE 512  // Blake2b

/**
 * HashState represents the internal state of a Hash.
 */
typedef struct {
  alignas(32) uint8_t opaque[HASH_MAX_CTX_SIZE];
} HashState;

/**
 * Hash represents an collision-resistant hash scheme.
 */
typedef struct {
  /** name of scheme */
  char name[100];
  /** length of key in bytes */
  uint8_t key_len;
  /** length of digest in bytes */
  uint8_t digest_len;

  int (*hash)(uint8_t *digest,
              size_t digest_len,
              const uint8_t *msg,
              size_t msg_len);
  int (*keyed_hash)(const uint8_t *key,
                    size_t key_len,
                    uint8_t *digest,
                    size_t digest_len,
                    const uint8_t *msg,
                    size_t msg_len);

  int (*init)(HashState *hash_ctx,
              const uint8_t *key,
              size_t key_len,
              size_t digest_len);
  int (*update)(HashState *hash_ctx, const uint8_t *in, size_t in_len);
  int (*final)(HashState *hash_ctx, uint8_t *digest, size_t digest_len);
} Hash;

const Hash *Hash_blake2b();
const Hash *Hash_sha256();
const Hash *Hash_ascon256();
const Hash *Hash_sha3_256();
const Hash *Hash_Sparkle512Sponge();
#ifdef CR_HAS_AREION
const Hash *Hash_Areion512Sponge();
const Hash *Hash_ODAreion512();
#endif

#ifdef __cplusplus
}
#endif

#endif  // CR_HASH_H
