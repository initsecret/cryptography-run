/*
   Simpira v2 reference C implementation

   Written in 2016 by Shay Gueron and Nicky Mouha

   This file implements only the 384-bit permutation, using AES intrinsics

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

#define B 3
#define ROUNDS (6 * B + 3)

#define C(i) \
  _mm_setr_epi32(0x00 ^ i ^ B, 0x10 ^ i ^ B, 0x20 ^ i ^ B, 0x30 ^ i ^ B)

#define R(x, y, z, i)                                   \
  do {                                                  \
    y = _mm_aesenc_si128(_mm_aesenc_si128(x, C(i)), y); \
  } while (0)

void perm(__m128i x[B]) {
  /* Type-I Generalized Feistel, cyclic shift */

  R(x[0], x[1], x[2], 1);
  R(x[1], x[2], x[0], 2);
  R(x[2], x[0], x[1], 3);
  R(x[0], x[1], x[2], 4);
  R(x[1], x[2], x[0], 5);
  R(x[2], x[0], x[1], 6);
  R(x[0], x[1], x[2], 7);
  R(x[1], x[2], x[0], 8);
  R(x[2], x[0], x[1], 9);
  R(x[0], x[1], x[2], 10);
  R(x[1], x[2], x[0], 11);
  R(x[2], x[0], x[1], 12);
  R(x[0], x[1], x[2], 13);
  R(x[1], x[2], x[0], 14);
  R(x[2], x[0], x[1], 15);
  R(x[0], x[1], x[2], 16);
  R(x[1], x[2], x[0], 17);
  R(x[2], x[0], x[1], 18);
  R(x[0], x[1], x[2], 19);
  R(x[1], x[2], x[0], 20);
  R(x[2], x[0], x[1], 21);
}

void invperm(__m128i x[B]) {
  /* Type-I Generalized Feistel, cyclic shift */

  R(x[2], x[0], x[1], 21);
  R(x[1], x[2], x[0], 20);
  R(x[0], x[1], x[2], 19);
  R(x[2], x[0], x[1], 18);
  R(x[1], x[2], x[0], 17);
  R(x[0], x[1], x[2], 16);
  R(x[2], x[0], x[1], 15);
  R(x[1], x[2], x[0], 14);
  R(x[0], x[1], x[2], 13);
  R(x[2], x[0], x[1], 12);
  R(x[1], x[2], x[0], 11);
  R(x[0], x[1], x[2], 10);
  R(x[2], x[0], x[1], 9);
  R(x[1], x[2], x[0], 8);
  R(x[0], x[1], x[2], 7);
  R(x[2], x[0], x[1], 6);
  R(x[1], x[2], x[0], 5);
  R(x[0], x[1], x[2], 4);
  R(x[2], x[0], x[1], 3);
  R(x[1], x[2], x[0], 2);
  R(x[0], x[1], x[2], 1);
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
