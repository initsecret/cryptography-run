/*
   Simpira v2 reference C implementation

   Written in 2016 by Shay Gueron and Nicky Mouha

   This file implements only the 512-bit permutation, using AES intrinsics

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

#define B 4
#define ROUNDS (6 * B - 9)

#define C0(i)                                                    \
  _mm_setr_epi32(0x00 ^ (2 * i + 1) ^ B, 0x10 ^ (2 * i + 1) ^ B, \
                 0x20 ^ (2 * i + 1) ^ B, 0x30 ^ (2 * i + 1) ^ B)
#define C1(i)                                                    \
  _mm_setr_epi32(0x00 ^ (2 * i + 2) ^ B, 0x10 ^ (2 * i + 2) ^ B, \
                 0x20 ^ (2 * i + 2) ^ B, 0x30 ^ (2 * i + 2) ^ B)

#define R(w, x, y, z, i)                                 \
  do {                                                   \
    x = _mm_aesenc_si128(_mm_aesenc_si128(w, C0(i)), x); \
    z = _mm_aesenc_si128(_mm_aesenc_si128(y, C1(i)), z); \
  } while (0)

static void perm(__m128i x[B]) {
  /* Type-II Feistel, cyclic shuffle */

  /* 15 rounds */
  R(x[0], x[1], x[2], x[3], 0);
  R(x[1], x[2], x[3], x[0], 1);
  R(x[2], x[3], x[0], x[1], 2);
  R(x[3], x[0], x[1], x[2], 3);

  R(x[0], x[1], x[2], x[3], 4);
  R(x[1], x[2], x[3], x[0], 5);
  R(x[2], x[3], x[0], x[1], 6);
  R(x[3], x[0], x[1], x[2], 7);

  R(x[0], x[1], x[2], x[3], 8);
  R(x[1], x[2], x[3], x[0], 9);
  R(x[2], x[3], x[0], x[1], 10);
  R(x[3], x[0], x[1], x[2], 11);

  R(x[0], x[1], x[2], x[3], 12);
  R(x[1], x[2], x[3], x[0], 13);
  R(x[2], x[3], x[0], x[1], 14);
}

static void invperm(__m128i x[B]) {
  /* Type 1.x Generalized Feistel, eta=2, cyclic shuffle */

  /* 15 rounds */
  R(x[2], x[3], x[0], x[1], 14);
  R(x[1], x[2], x[3], x[0], 13);
  R(x[0], x[1], x[2], x[3], 12);

  R(x[3], x[0], x[1], x[2], 11);
  R(x[2], x[3], x[0], x[1], 10);
  R(x[1], x[2], x[3], x[0], 9);
  R(x[0], x[1], x[2], x[3], 8);

  R(x[3], x[0], x[1], x[2], 7);
  R(x[2], x[3], x[0], x[1], 6);
  R(x[1], x[2], x[3], x[0], 5);
  R(x[0], x[1], x[2], x[3], 4);

  R(x[3], x[0], x[1], x[2], 3);
  R(x[2], x[3], x[0], x[1], 2);
  R(x[1], x[2], x[3], x[0], 1);
  R(x[0], x[1], x[2], x[3], 0);
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

static const uint8_t perm_simpira512_state_len = 64;

static int perm_simpira512_forward(uint8_t *in_state, uint8_t *out_state) {
  __m128i state[4];
  state[0] = load128(in_state);
  state[1] = load128(in_state + 16);
  state[2] = load128(in_state + 32);
  state[3] = load128(in_state + 48);
  perm(state);
  store128(out_state, state[0]);
  store128(out_state + 16, state[1]);
  store128(out_state + 32, state[2]);
  store128(out_state + 48, state[3]);
  return 1;
}

static int perm_simpira512_backward(uint8_t *in_state, uint8_t *out_state) {
  __m128i state[4];
  state[0] = load128(in_state);
  state[1] = load128(in_state + 16);
  state[2] = load128(in_state + 32);
  state[3] = load128(in_state + 48);
  invperm(state);
  store128(out_state, state[0]);
  store128(out_state + 16, state[1]);
  store128(out_state + 32, state[2]);
  store128(out_state + 48, state[3]);
  return 1;
}

static const Permutation simpira512 = {
    "Simpira512",
    perm_simpira512_state_len,
    perm_simpira512_forward,
    perm_simpira512_backward,
};

const Permutation *Permutation_Simpira512() {
  return &simpira512;
}
