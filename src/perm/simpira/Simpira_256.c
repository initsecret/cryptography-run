/*
   Simpira v2 reference C implementation

   Written in 2016 by Shay Gueron and Nicky Mouha

   This file implements only the 256-bit permutation, using AES intrinsics

   To the extent possible under law, the author has dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along
   with this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.
*/
#include <immintrin.h>
#include <stdint.h>
// #include <stdio.h>

#define B 2
#define ROUNDS (6 * B + 3)

#define C(i) \
  _mm_setr_epi32(0x00 ^ i ^ B, 0x10 ^ i ^ B, 0x20 ^ i ^ B, 0x30 ^ i ^ B)

#define R(y, z, i)                                      \
  do {                                                  \
    z = _mm_aesenc_si128(_mm_aesenc_si128(y, C(i)), z); \
  } while (0)

static void perm(__m128i x[B]) {
  /* Feistel */

  R(x[0], x[1], 1);
  R(x[1], x[0], 2);
  R(x[0], x[1], 3);
  R(x[1], x[0], 4);
  R(x[0], x[1], 5);
  R(x[1], x[0], 6);
  R(x[0], x[1], 7);
  R(x[1], x[0], 8);
  R(x[0], x[1], 9);
  R(x[1], x[0], 10);
  R(x[0], x[1], 11);
  R(x[1], x[0], 12);
  R(x[0], x[1], 13);
  R(x[1], x[0], 14);
  R(x[0], x[1], 15);
}

static void invperm(__m128i x[B]) {
  /* Feistel */

  R(x[0], x[1], 15);
  R(x[1], x[0], 14);
  R(x[0], x[1], 13);
  R(x[1], x[0], 12);
  R(x[0], x[1], 11);
  R(x[1], x[0], 10);
  R(x[0], x[1], 9);
  R(x[1], x[0], 8);
  R(x[0], x[1], 7);
  R(x[1], x[0], 6);
  R(x[0], x[1], 5);
  R(x[1], x[0], 4);
  R(x[0], x[1], 3);
  R(x[1], x[0], 2);
  R(x[0], x[1], 1);
}

// void print(__m128i x[B]) {
//   int i;
//   uint32_t *v = (uint32_t *)&x[0];

//   for (i = 0; i < B; i++) {
//     printf("%08x %08x %08x %08x ", v[4 * i], v[4 * i + 1], v[4 * i + 2],
//            v[4 * i + 3]);
//   }
//   printf("\n");
// }

// int main(int argc, char *argv[]) {
//   __m128i x[B] = {{0}};

//   printf("x: ");
//   print(x);

//   perm(x);

//   printf("y: ");
//   print(x);

//   invperm(x);

//   printf("x: ");
//   print(x);

//   return 0;
// }

/* ------------------------------------------------------------------------- */
/* Permutation interface                                                     */

#include <assert.h>

#include <cryptography-run/perm.h>
#include "../../internal.h"

static const uint8_t perm_simpira256_state_len = 32;

static int perm_simpira256_forward(uint8_t *in_state, uint8_t *out_state) {
  __m128i state[2];
  state[0] = load128(in_state);
  state[1] = load128(in_state + 16);
  perm(state);
  store128(out_state, state[0]);
  store128(out_state + 16, state[1]);
  return 1;
}

static int perm_simpira256_backward(uint8_t *in_state, uint8_t *out_state) {
  __m128i state[2];
  state[0] = load128(in_state);
  state[1] = load128(in_state + 16);
  invperm(state);
  store128(out_state, state[0]);
  store128(out_state + 16, state[1]);
  return 1;
}

static const Permutation simpira256 = {
    "Simpira256",
    perm_simpira256_state_len,
    perm_simpira256_forward,
    perm_simpira256_backward,
};

const Permutation *Permutation_Simpira256() {
  return &simpira256;
}
