/*
    Even-Mansour with a 256-bit permutation

    :copyright: (c) 2025 by OCH authors.
    :license: Creative Commons CC0 1.0
*/

#ifndef CR_EM256_H
#define CR_EM256_H

#include <assert.h>
#include <stdalign.h>

#include <cryptography-run/base.h>
#include <cryptography-run/gf256.h>

#include <cryptography-run/aead.h>

#if defined(__cplusplus)
extern "C" {
#endif

typedef u256_t block;

typedef u256_t EMKey;
typedef u256_t EMOffset;

// Size of OCT256 offset table to precompute
#define L_TABLE_SIZE 16

/** EM256 represents an instance of Even-Mansour with 256-bit block size. */
typedef struct {
  /** name of scheme */
  char name[100];
  /** unique id of scheme */
  uint8_t crid[2];
  /** Encrypts |inout| in-place using |offset|.  */
  void (*EM_encrypt)(const EMOffset offset, u256_t *inout);
  /** Decrypts |inout| in-place using |offset|.   */
  void (*EM_decrypt)(const EMOffset offset, u256_t *inout);
  /** Encrypts |inout| in-place using |offset|.  */
  void (*EM_encrypt_x4)(const EMOffset offset[4], u256_t inout[4]);
  /** Encrypts |inout| in-place using |offset|.  */
  void (*EM_encrypt_x8)(const EMOffset offset[8], u256_t inout[8]);
} EM256;

const EM256 *EM_Sparkle256();
const EM256 *EM_Areion256();

#ifdef __cplusplus
}
#endif

#endif  // CR_EM256_H