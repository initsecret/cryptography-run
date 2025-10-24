#ifndef CR_AWSLC_INTERNAL_H
#define CR_AWSLC_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <cryptography-run/base.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct {
  uint64_t hi, lo;
} u128;

// AES_MAXNR is the maximum number of AES rounds.
#define AES_MAXNR 14

// aes_key_st should be an opaque type, but EVP requires that the size be
// known.
struct aes_key_st {
  uint32_t rd_key[4 * (AES_MAXNR + 1)];
  unsigned rounds;
};
typedef struct aes_key_st AES_KEY;

// These functions are defined in ./aarch64/aesv8-gcm-armv8.pl.
void aes_gcm_enc_kernel(const uint8_t *in,
                        uint64_t in_bits,
                        void *out,
                        void *Xi,
                        uint8_t *ivec,
                        const AES_KEY *key,
                        const u128 Htable[16]);
void aes_gcm_dec_kernel(const uint8_t *in,
                        uint64_t in_bits,
                        void *out,
                        void *Xi,
                        uint8_t *ivec,
                        const AES_KEY *key,
                        const u128 Htable[16]);

#ifdef __cplusplus
}
#endif

#endif  // CR_AWSLC_INTERNAL_H