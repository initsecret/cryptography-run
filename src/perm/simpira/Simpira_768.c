/*
   Simpira v2 reference C implementation

   Written in 2016 by Shay Gueron and Nicky Mouha

   This file implements only the 768-bit permutation, using AES intrinsics

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

#define B 6
#define ROUNDS (3 * 5)

#define C0(i)                                                    \
  _mm_setr_epi32(0x00 ^ (3 * i + 1) ^ B, 0x10 ^ (3 * i + 1) ^ B, \
                 0x20 ^ (3 * i + 1) ^ B, 0x30 ^ (3 * i + 1) ^ B)
#define C1(i)                                                    \
  _mm_setr_epi32(0x00 ^ (3 * i + 2) ^ B, 0x10 ^ (3 * i + 2) ^ B, \
                 0x20 ^ (3 * i + 2) ^ B, 0x30 ^ (3 * i + 2) ^ B)
#define C2(i)                                                    \
  _mm_setr_epi32(0x00 ^ (3 * i + 3) ^ B, 0x10 ^ (3 * i + 3) ^ B, \
                 0x20 ^ (3 * i + 3) ^ B, 0x30 ^ (3 * i + 3) ^ B)

#define R(u, v, w, x, y, z, i)                           \
  do {                                                   \
    v = _mm_aesenc_si128(_mm_aesenc_si128(u, C0(i)), v); \
    x = _mm_aesenc_si128(_mm_aesenc_si128(w, C1(i)), x); \
    z = _mm_aesenc_si128(_mm_aesenc_si128(y, C2(i)), z); \
  } while (0)

void perm(__m128i b[B]) {
  /* Type-II Generalized Feistel, Suzaki-Minematsu shuffle (3,0,1,4,5,2) */

  R(b[0], b[1], b[2], b[3], b[4], b[5], 0);
  R(b[1], b[2], b[5], b[0], b[3], b[4], 1);
  R(b[2], b[5], b[4], b[1], b[0], b[3], 2);
  R(b[5], b[4], b[3], b[2], b[1], b[0], 3);
  R(b[4], b[3], b[0], b[5], b[2], b[1], 4);
  R(b[3], b[0], b[1], b[4], b[5], b[2], 5);
  R(b[0], b[1], b[2], b[3], b[4], b[5], 6);
  R(b[1], b[2], b[5], b[0], b[3], b[4], 7);
  R(b[2], b[5], b[4], b[1], b[0], b[3], 8);
  R(b[5], b[4], b[3], b[2], b[1], b[0], 9);
  R(b[4], b[3], b[0], b[5], b[2], b[1], 10);
  R(b[3], b[0], b[1], b[4], b[5], b[2], 11);
  R(b[0], b[1], b[2], b[3], b[4], b[5], 12);
  R(b[1], b[2], b[5], b[0], b[3], b[4], 13);
  R(b[2], b[5], b[4], b[1], b[0], b[3], 14);
}

void invperm(__m128i b[B]) {
  /* Type-II Generalized Feistel, Suzaki-Minematsu shuffle (3,0,1,4,5,2) */

  R(b[2], b[5], b[4], b[1], b[0], b[3], 14);
  R(b[1], b[2], b[5], b[0], b[3], b[4], 13);
  R(b[0], b[1], b[2], b[3], b[4], b[5], 12);
  R(b[3], b[0], b[1], b[4], b[5], b[2], 11);
  R(b[4], b[3], b[0], b[5], b[2], b[1], 10);
  R(b[5], b[4], b[3], b[2], b[1], b[0], 9);
  R(b[2], b[5], b[4], b[1], b[0], b[3], 8);
  R(b[1], b[2], b[5], b[0], b[3], b[4], 7);
  R(b[0], b[1], b[2], b[3], b[4], b[5], 6);
  R(b[3], b[0], b[1], b[4], b[5], b[2], 5);
  R(b[4], b[3], b[0], b[5], b[2], b[1], 4);
  R(b[5], b[4], b[3], b[2], b[1], b[0], 3);
  R(b[2], b[5], b[4], b[1], b[0], b[3], 2);
  R(b[1], b[2], b[5], b[0], b[3], b[4], 1);
  R(b[0], b[1], b[2], b[3], b[4], b[5], 0);
}

void print(__m128i x[B]) {
  int i;
  uint32_t *v = (uint32_t *)&x[0];

  for (i = 0; i < B; i++) {
    printf("%08x %08x %08x %08x ", v[4 * i], v[4 * i + 1], v[4 * i + 2],
           v[4 * i + 3]);
  }
  printf("\n");
}

int main(int argc, char *argv[]) {
  __m128i x[B] = {{0}};

  printf("x: ");
  print(x);

  perm(x);

  printf("y: ");
  print(x);

  invperm(x);

  printf("x: ");
  print(x);

  return 0;
}
