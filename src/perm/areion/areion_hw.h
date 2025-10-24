/* Hardware implementation of Areion256 and Areion512 based on
 * https://github.com/gmo-ierae/low-latency-crypto-areion/tree/ccc9cd619940ee2d1ab34b9c21b31bf3510789b8
 * and Appendix A and B of https://eprint.iacr.org/2023/794.pdf
 */

/* Copyright (c) 2023 GMO Cybersecurity by Ierae, Inc. All rights reserved. */
/* This software is implemented based on the algorithms designed in the
 * following research paper. */
/* see: https://eprint.iacr.org/2023/794 */

#ifndef AREION_X64_H
#define AREION_X64_H

#include <cryptography-run/base.h>
#include <stdint.h>

#ifdef CR_HAS_AREION

/* Round Constant aligned for little endian */
static const uint32_t RC[][4] = {
    {0x03707344, 0x13198a2e, 0x85a308d3, 0x243f6a88},
    {0xec4e6c89, 0x082efa98, 0x299f31d0, 0xa4093822},
    {0x34e90c6c, 0xbe5466cf, 0x38d01377, 0x452821e6},
    {0xb5470917, 0x3f84d5b5, 0xc97c50dd, 0xc0ac29b7},
    {0x98dfb5ac, 0xd1310ba6, 0x8979fb1b, 0x9216d5d9},
    {0x6a267e96, 0xb8e1afed, 0xd01adfb7, 0x2ffd72db},
    {0xb3916cf7, 0x24a19947, 0xf12c7f99, 0xba7c9045},
    {0x1574e690, 0x36920d87, 0x58efc166, 0x801f2e28},
    {0x728eb658, 0x0d95748f, 0xf4933d7e, 0xa458fea3},
    {0xc25a59b5, 0x7b54a41d, 0x82154aee, 0x718bcd58},
    {0x286085f0, 0xc5d1b023, 0x2af26013, 0x9c30d539},
    {0x603a180e, 0x8e79dcb0, 0xb8db38ef, 0xca417918},
    {0xbd314b27, 0xd71577c1, 0xb01e8a3e, 0x6c9e0e8b},
    {0xaa55ab94, 0xe65525f3, 0x55605c60, 0x78af2fda},
    {0x2aab10b6, 0x55ca396a, 0x63e81440, 0x57489862},
    {0x7c72e993, 0xa15486af, 0x1141e8ce, 0xb4cc5c34},
    {0x741831f6, 0x2ba9c55d, 0x636fbc2a, 0xb3ee1411},
    {0x6c24cf5c, 0xafd6ba33, 0x9b87931e, 0xce5c3e16},
    {0x6b4bb9af, 0x3b8f4898, 0x28958677, 0x7a325381},
    {0xfb21a991, 0x61d809cc, 0x66282193, 0xc4bfe81b},
    {0xe98575b1, 0xef845d5d, 0x5dec8032, 0x487cac60},
    {0xd396acc5, 0x23893e81, 0xeb651b88, 0xdc262302},
    {0x48420040, 0xe0b4482a, 0x3f442392, 0xf6d6ff38},
    {0xf6e96c9a, 0x21c66842, 0x9e1f9b5e, 0x69c8f04a}};

#if CR_INTEL_HW
#include <immintrin.h>

#define RC0(i) _mm_setr_epi32(RC[i][0], RC[i][1], RC[i][2], RC[i][3])
#define RC1(i) _mm_setr_epi32(0, 0, 0, 0)

#define AES_ENC(State, RoundKey) _mm_aesenc_si128((State), (RoundKey))
#define AES_ENC_LAST(State, RoundKey) _mm_aesenclast_si128((State), (RoundKey))
#define AES_DEC(State, RoundKey) _mm_aesdec_si128((State), (RoundKey))
#define AES_DEC_LAST(State, RoundKey) _mm_aesdeclast_si128((State), (RoundKey))
#define AES_IMC(State) _mm_aesimc_si128((State))

#elif CR_ARM_HW
#include <arm_neon.h>

#define RC0(i) vreinterpretq_u8_u32(vld1q_u32(RC[i]))
#define RC1(i) vmovq_n_u8(0)

// Emulate Intel AES instructions on ARM
// https://blog.michaelbrase.com/2018/05/08/emulating-x86-aes-intrinsics-on-armv8-a/
// The code in Appendix B of https://eprint.iacr.org/2023/794.pdf might be more
// efficient but that code wasn't producing an invertible permutation and also
// wasn't matching test vectors so we chose this simpler path.
#define ALL_ZEROS vmovq_n_u8(0)

#define AES_ENC(State, RoundKey) \
  veorq_u8(vaesmcq_u8(vaeseq_u8((State), ALL_ZEROS)), (RoundKey))
#define AES_ENC_LAST(State, RoundKey) \
  veorq_u8(vaeseq_u8((State), ALL_ZEROS), (RoundKey))
#define AES_DEC(State, RoundKey) \
  veorq_u8(vaesimcq_u8(vaesdq_u8((State), ALL_ZEROS)), (RoundKey))
#define AES_DEC_LAST(State, RoundKey) \
  veorq_u8(vaesdq_u8((State), ALL_ZEROS), (RoundKey))
// XXX: this AES_IMC is wrong
// #define AES_IMC(State) vaesimcq_u8((State))
#endif

/* Round Function for the 256-bit permutation */
#define Round_Function_256(x0, x1, i)      \
  do {                                     \
    x1 = AES_ENC(AES_ENC(x0, RC0(i)), x1); \
    x0 = AES_ENC_LAST(x0, RC1(i));         \
  } while (0)

/* Inversed Round Function for the 256-bit permutation */
#define Inv_Round_Function_256(x0, x1, i)  \
  do {                                     \
    x0 = AES_DEC_LAST(x0, RC1(i));         \
    x1 = AES_ENC(AES_ENC(x0, RC0(i)), x1); \
  } while (0)

/* Round Function for the 512-bit permutation */
#define Round_Function_512(x0, x1, x2, x3, i)       \
  do {                                              \
    x1 = AES_ENC(x0, x1);                           \
    x3 = AES_ENC(x2, x3);                           \
    x0 = AES_ENC_LAST(x0, RC1(i));                  \
    x2 = AES_ENC(AES_ENC_LAST(x2, RC0(i)), RC1(i)); \
  } while (0)

#if CR_INTEL_HW
/* Inversed Round Function or the 512-bit permutation */
#define Inv_Round_Function_512(x0, x1, x2, x3, i) \
  do {                                            \
    x0 = AES_DEC_LAST(x0, RC1(i));                \
    x2 = AES_DEC_LAST(AES_IMC(x2), RC0(i));       \
    x2 = AES_DEC_LAST(x2, RC1(i));                \
    x1 = AES_ENC(x0, x1);                         \
    x3 = AES_ENC(x2, x3);                         \
  } while (0)
#endif

/* 256-bit permutation */
#define perm256(x0, x1)            \
  do {                             \
    Round_Function_256(x0, x1, 0); \
    Round_Function_256(x1, x0, 1); \
    Round_Function_256(x0, x1, 2); \
    Round_Function_256(x1, x0, 3); \
    Round_Function_256(x0, x1, 4); \
    Round_Function_256(x1, x0, 5); \
    Round_Function_256(x0, x1, 6); \
    Round_Function_256(x1, x0, 7); \
    Round_Function_256(x0, x1, 8); \
    Round_Function_256(x1, x0, 9); \
  } while (0)

/* 256-bit permutation two-interleaved */
#define perm256x2(x0, x1)                \
  do {                                   \
    Round_Function_256(x0[0], x1[0], 0); \
    Round_Function_256(x0[1], x1[1], 0); \
    Round_Function_256(x1[0], x0[0], 1); \
    Round_Function_256(x1[1], x0[1], 1); \
    Round_Function_256(x0[0], x1[0], 2); \
    Round_Function_256(x0[1], x1[1], 2); \
    Round_Function_256(x1[0], x0[0], 3); \
    Round_Function_256(x1[1], x0[1], 3); \
    Round_Function_256(x0[0], x1[0], 4); \
    Round_Function_256(x0[1], x1[1], 4); \
    Round_Function_256(x1[0], x0[0], 5); \
    Round_Function_256(x1[1], x0[1], 5); \
    Round_Function_256(x0[0], x1[0], 6); \
    Round_Function_256(x0[1], x1[1], 6); \
    Round_Function_256(x1[0], x0[0], 7); \
    Round_Function_256(x1[1], x0[1], 7); \
    Round_Function_256(x0[0], x1[0], 8); \
    Round_Function_256(x0[1], x1[1], 8); \
    Round_Function_256(x1[0], x0[0], 9); \
    Round_Function_256(x1[1], x0[1], 9); \
  } while (0)

/* 256-bit permutation four-interleaved */
#define perm256x4(x0_0, x1_0, x0_1, x1_1, x0_2, x1_2, x0_3, x1_3) \
  do {                                                            \
    Round_Function_256(x0_0, x1_0, 0);                            \
    Round_Function_256(x0_1, x1_1, 0);                            \
    Round_Function_256(x0_2, x1_2, 0);                            \
    Round_Function_256(x0_3, x1_3, 0);                            \
    Round_Function_256(x1_0, x0_0, 1);                            \
    Round_Function_256(x1_1, x0_1, 1);                            \
    Round_Function_256(x1_2, x0_2, 1);                            \
    Round_Function_256(x1_3, x0_3, 1);                            \
    Round_Function_256(x0_0, x1_0, 2);                            \
    Round_Function_256(x0_1, x1_1, 2);                            \
    Round_Function_256(x0_2, x1_2, 2);                            \
    Round_Function_256(x0_3, x1_3, 2);                            \
    Round_Function_256(x1_0, x0_0, 3);                            \
    Round_Function_256(x1_1, x0_1, 3);                            \
    Round_Function_256(x1_2, x0_2, 3);                            \
    Round_Function_256(x1_3, x0_3, 3);                            \
    Round_Function_256(x0_0, x1_0, 4);                            \
    Round_Function_256(x0_1, x1_1, 4);                            \
    Round_Function_256(x0_2, x1_2, 4);                            \
    Round_Function_256(x0_3, x1_3, 4);                            \
    Round_Function_256(x1_0, x0_0, 5);                            \
    Round_Function_256(x1_1, x0_1, 5);                            \
    Round_Function_256(x1_2, x0_2, 5);                            \
    Round_Function_256(x1_3, x0_3, 5);                            \
    Round_Function_256(x0_0, x1_0, 6);                            \
    Round_Function_256(x0_1, x1_1, 6);                            \
    Round_Function_256(x0_2, x1_2, 6);                            \
    Round_Function_256(x0_3, x1_3, 6);                            \
    Round_Function_256(x1_0, x0_0, 7);                            \
    Round_Function_256(x1_1, x0_1, 7);                            \
    Round_Function_256(x1_2, x0_2, 7);                            \
    Round_Function_256(x1_3, x0_3, 7);                            \
    Round_Function_256(x0_0, x1_0, 8);                            \
    Round_Function_256(x0_1, x1_1, 8);                            \
    Round_Function_256(x0_2, x1_2, 8);                            \
    Round_Function_256(x0_3, x1_3, 8);                            \
    Round_Function_256(x1_0, x0_0, 9);                            \
    Round_Function_256(x1_1, x0_1, 9);                            \
    Round_Function_256(x1_2, x0_2, 9);                            \
    Round_Function_256(x1_3, x0_3, 9);                            \
  } while (0)

/* 256-bit permutation eight interleaved */
#define perm256x8(x0_0, x1_0, x0_1, x1_1, x0_2, x1_2, x0_3, x1_3, x0_4, x1_4, \
                  x0_5, x1_5, x0_6, x1_6, x0_7, x1_7)                         \
  do {                                                                        \
    Round_Function_256(x0_0, x1_0, 0);                                        \
    Round_Function_256(x0_1, x1_1, 0);                                        \
    Round_Function_256(x0_2, x1_2, 0);                                        \
    Round_Function_256(x0_3, x1_3, 0);                                        \
    Round_Function_256(x0_4, x1_4, 0);                                        \
    Round_Function_256(x0_5, x1_5, 0);                                        \
    Round_Function_256(x0_6, x1_6, 0);                                        \
    Round_Function_256(x0_7, x1_7, 0);                                        \
    Round_Function_256(x1_0, x0_0, 1);                                        \
    Round_Function_256(x1_1, x0_1, 1);                                        \
    Round_Function_256(x1_2, x0_2, 1);                                        \
    Round_Function_256(x1_3, x0_3, 1);                                        \
    Round_Function_256(x1_4, x0_4, 1);                                        \
    Round_Function_256(x1_5, x0_5, 1);                                        \
    Round_Function_256(x1_6, x0_6, 1);                                        \
    Round_Function_256(x1_7, x0_7, 1);                                        \
    Round_Function_256(x0_0, x1_0, 2);                                        \
    Round_Function_256(x0_1, x1_1, 2);                                        \
    Round_Function_256(x0_2, x1_2, 2);                                        \
    Round_Function_256(x0_3, x1_3, 2);                                        \
    Round_Function_256(x0_4, x1_4, 2);                                        \
    Round_Function_256(x0_5, x1_5, 2);                                        \
    Round_Function_256(x0_6, x1_6, 2);                                        \
    Round_Function_256(x0_7, x1_7, 2);                                        \
    Round_Function_256(x1_0, x0_0, 3);                                        \
    Round_Function_256(x1_1, x0_1, 3);                                        \
    Round_Function_256(x1_2, x0_2, 3);                                        \
    Round_Function_256(x1_3, x0_3, 3);                                        \
    Round_Function_256(x1_4, x0_4, 3);                                        \
    Round_Function_256(x1_5, x0_5, 3);                                        \
    Round_Function_256(x1_6, x0_6, 3);                                        \
    Round_Function_256(x1_7, x0_7, 3);                                        \
    Round_Function_256(x0_0, x1_0, 4);                                        \
    Round_Function_256(x0_1, x1_1, 4);                                        \
    Round_Function_256(x0_2, x1_2, 4);                                        \
    Round_Function_256(x0_3, x1_3, 4);                                        \
    Round_Function_256(x0_4, x1_4, 4);                                        \
    Round_Function_256(x0_5, x1_5, 4);                                        \
    Round_Function_256(x0_6, x1_6, 4);                                        \
    Round_Function_256(x0_7, x1_7, 4);                                        \
    Round_Function_256(x1_0, x0_0, 5);                                        \
    Round_Function_256(x1_1, x0_1, 5);                                        \
    Round_Function_256(x1_2, x0_2, 5);                                        \
    Round_Function_256(x1_3, x0_3, 5);                                        \
    Round_Function_256(x1_4, x0_4, 5);                                        \
    Round_Function_256(x1_5, x0_5, 5);                                        \
    Round_Function_256(x1_6, x0_6, 5);                                        \
    Round_Function_256(x1_7, x0_7, 5);                                        \
    Round_Function_256(x0_0, x1_0, 6);                                        \
    Round_Function_256(x0_1, x1_1, 6);                                        \
    Round_Function_256(x0_2, x1_2, 6);                                        \
    Round_Function_256(x0_3, x1_3, 6);                                        \
    Round_Function_256(x0_4, x1_4, 6);                                        \
    Round_Function_256(x0_5, x1_5, 6);                                        \
    Round_Function_256(x0_6, x1_6, 6);                                        \
    Round_Function_256(x0_7, x1_7, 6);                                        \
    Round_Function_256(x1_0, x0_0, 7);                                        \
    Round_Function_256(x1_1, x0_1, 7);                                        \
    Round_Function_256(x1_2, x0_2, 7);                                        \
    Round_Function_256(x1_3, x0_3, 7);                                        \
    Round_Function_256(x1_4, x0_4, 7);                                        \
    Round_Function_256(x1_5, x0_5, 7);                                        \
    Round_Function_256(x1_6, x0_6, 7);                                        \
    Round_Function_256(x1_7, x0_7, 7);                                        \
    Round_Function_256(x0_0, x1_0, 8);                                        \
    Round_Function_256(x0_1, x1_1, 8);                                        \
    Round_Function_256(x0_2, x1_2, 8);                                        \
    Round_Function_256(x0_3, x1_3, 8);                                        \
    Round_Function_256(x0_4, x1_4, 8);                                        \
    Round_Function_256(x0_5, x1_5, 8);                                        \
    Round_Function_256(x0_6, x1_6, 8);                                        \
    Round_Function_256(x0_7, x1_7, 8);                                        \
    Round_Function_256(x1_0, x0_0, 9);                                        \
    Round_Function_256(x1_1, x0_1, 9);                                        \
    Round_Function_256(x1_2, x0_2, 9);                                        \
    Round_Function_256(x1_3, x0_3, 9);                                        \
    Round_Function_256(x1_4, x0_4, 9);                                        \
    Round_Function_256(x1_5, x0_5, 9);                                        \
    Round_Function_256(x1_6, x0_6, 9);                                        \
    Round_Function_256(x1_7, x0_7, 9);                                        \
  } while (0)

/* Inversed 256-bit permutation */
#define Inv_perm256(x0, x1)            \
  do {                                 \
    Inv_Round_Function_256(x1, x0, 9); \
    Inv_Round_Function_256(x0, x1, 8); \
    Inv_Round_Function_256(x1, x0, 7); \
    Inv_Round_Function_256(x0, x1, 6); \
    Inv_Round_Function_256(x1, x0, 5); \
    Inv_Round_Function_256(x0, x1, 4); \
    Inv_Round_Function_256(x1, x0, 3); \
    Inv_Round_Function_256(x0, x1, 2); \
    Inv_Round_Function_256(x1, x0, 1); \
    Inv_Round_Function_256(x0, x1, 0); \
  } while (0)

/* 512-bit permutation */
#define perm512(x0, x1, x2, x3)             \
  do {                                      \
    Round_Function_512(x0, x1, x2, x3, 0);  \
    Round_Function_512(x1, x2, x3, x0, 1);  \
    Round_Function_512(x2, x3, x0, x1, 2);  \
    Round_Function_512(x3, x0, x1, x2, 3);  \
    Round_Function_512(x0, x1, x2, x3, 4);  \
    Round_Function_512(x1, x2, x3, x0, 5);  \
    Round_Function_512(x2, x3, x0, x1, 6);  \
    Round_Function_512(x3, x0, x1, x2, 7);  \
    Round_Function_512(x0, x1, x2, x3, 8);  \
    Round_Function_512(x1, x2, x3, x0, 9);  \
    Round_Function_512(x2, x3, x0, x1, 10); \
    Round_Function_512(x3, x0, x1, x2, 11); \
    Round_Function_512(x0, x1, x2, x3, 12); \
    Round_Function_512(x1, x2, x3, x0, 13); \
    Round_Function_512(x2, x3, x0, x1, 14); \
  } while (0)

#if CR_INTEL_HW
/* Inversed 512-bit permutation */
#define Inv_perm512(x0, x1, x2, x3)             \
  do {                                          \
    Inv_Round_Function_512(x2, x3, x0, x1, 14); \
    Inv_Round_Function_512(x1, x2, x3, x0, 13); \
    Inv_Round_Function_512(x0, x1, x2, x3, 12); \
    Inv_Round_Function_512(x3, x0, x1, x2, 11); \
    Inv_Round_Function_512(x2, x3, x0, x1, 10); \
    Inv_Round_Function_512(x1, x2, x3, x0, 9);  \
    Inv_Round_Function_512(x0, x1, x2, x3, 8);  \
    Inv_Round_Function_512(x3, x0, x1, x2, 7);  \
    Inv_Round_Function_512(x2, x3, x0, x1, 6);  \
    Inv_Round_Function_512(x1, x2, x3, x0, 5);  \
    Inv_Round_Function_512(x0, x1, x2, x3, 4);  \
    Inv_Round_Function_512(x3, x0, x1, x2, 3);  \
    Inv_Round_Function_512(x2, x3, x0, x1, 2);  \
    Inv_Round_Function_512(x1, x2, x3, x0, 1);  \
    Inv_Round_Function_512(x0, x1, x2, x3, 0);  \
  } while (0)
#endif

#endif  // CR_HAS_AREION

#endif  // AREION_X64_H
