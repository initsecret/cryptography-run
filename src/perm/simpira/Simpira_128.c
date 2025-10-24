/*
   Simpira v2 reference C implementation

   Written in 2016 by Shay Gueron and Nicky Mouha

   This file implements only the 128-bit permutation, using AES intrinsics

   To the extent possible under law, the author has dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along
   with this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.
*/
#include <immintrin.h>
#include <stdint.h>
#include <stdio.h>

#define B 1
#define ROUNDS (6 * B)

#define Z _mm_setr_epi32(0, 0, 0, 0)
#define C(i) \
  _mm_setr_epi32(0x00 ^ i ^ B, 0x10 ^ i ^ B, 0x20 ^ i ^ B, 0x30 ^ i ^ B)
#define Ci(i)       \
  _mm_aesimc_si128( \
      _mm_setr_epi32(0x00 ^ i ^ B, 0x10 ^ i ^ B, 0x20 ^ i ^ B, 0x30 ^ i ^ B))

void perm(__m128i x[1]) {
  /* AES permutation */

  x[0] = _mm_aesenc_si128(x[0], C(1));
  x[0] = _mm_aesenc_si128(x[0], Z);
  x[0] = _mm_aesenc_si128(x[0], C(2));
  x[0] = _mm_aesenc_si128(x[0], Z);
  x[0] = _mm_aesenc_si128(x[0], C(3));
  x[0] = _mm_aesenc_si128(x[0], Z);
  x[0] = _mm_aesenc_si128(x[0], C(4));
  x[0] = _mm_aesenc_si128(x[0], Z);
  x[0] = _mm_aesenc_si128(x[0], C(5));
  x[0] = _mm_aesenc_si128(x[0], Z);
  x[0] = _mm_aesenc_si128(x[0], C(6));
  x[0] = _mm_aesenclast_si128(x[0], Z);
}

void invperm(__m128i x[1]) {
  /* AES permutation */

  x[0] = _mm_aesdec_si128(x[0], Ci(6));
  x[0] = _mm_aesdec_si128(x[0], Z);
  x[0] = _mm_aesdec_si128(x[0], Ci(5));
  x[0] = _mm_aesdec_si128(x[0], Z);
  x[0] = _mm_aesdec_si128(x[0], Ci(4));
  x[0] = _mm_aesdec_si128(x[0], Z);
  x[0] = _mm_aesdec_si128(x[0], Ci(3));
  x[0] = _mm_aesdec_si128(x[0], Z);
  x[0] = _mm_aesdec_si128(x[0], Ci(2));
  x[0] = _mm_aesdec_si128(x[0], Z);
  x[0] = _mm_aesdec_si128(x[0], Ci(1));
  x[0] = _mm_aesdeclast_si128(x[0], Z);
}

void print(__m128i x) {
  uint32_t *v = (uint32_t *)&x;

  printf("%08x %08x %08x %08x \n", v[0], v[1], v[2], v[3]);
}

int main(int argc, char *argv[]) {
  __m128i x = {0};

  printf("x: ");
  print(x);

  perm(&x);

  printf("y: ");
  print(x);

  invperm(&x);

  printf("x: ");
  print(x);

  return 0;
}
