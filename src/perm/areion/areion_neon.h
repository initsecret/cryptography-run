/* From Appendix A.3 of https://eprint.iacr.org/2023/794 */

// FIXME: remove this file

#ifndef AREION_NEON_H
#define AREION_NEON_H

#ifdef __ARM_NEON

#include <arm_neon.h>
#include <stdint.h>

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
#define RC0 vmovq_n_u8(0)
#define RC1(i) vreinterpretq_u8_u32(vld1q_u32(RC[i]))

/* Operations for the round function */
#define A1(X, K) vaesmcq_u8((vaeseq_u8(X, K)))
#define A2(X, K) vaeseq_u8(X, K)
#define A3(X) vaesmcq_u8(X)
#define A4(X, K) vaesdq_u8(X, K)
#define XOR(X, Y) veorq_u8(X, Y)

/* Round Function for the 256-bit permutation */
#define R256_FIRST(x0, x1, i)             \
  do {                                    \
    x1 = A2(A1(A1(x0, RC0), RC1(i)), x1); \
    x0 = A2(x0, RC0);                     \
  } while (0)
#define R256_MIDDLE(x0, x1, i)            \
  do {                                    \
    x1 = A2(A1(A1(x0, RC0), RC1(i)), x1); \
  } while (0)
#define R256_LAST(x0, x1, i)               \
  do {                                     \
    x1 = XOR(A1(A1(x0, RC0), RC1(i)), x1); \
    x0 = A2(x0, RC0);                      \
  } while (0)

/* 256-bit permutation */
#define perm256(x0, x1)     \
  do {                      \
    R256_FIRST(x0, x1, 0);  \
    R256_MIDDLE(x1, x0, 1); \
    R256_MIDDLE(x0, x1, 2); \
    R256_MIDDLE(x1, x0, 3); \
    R256_MIDDLE(x0, x1, 4); \
    R256_MIDDLE(x1, x0, 5); \
    R256_MIDDLE(x0, x1, 6); \
    R256_MIDDLE(x1, x0, 7); \
    R256_MIDDLE(x0, x1, 8); \
    R256_LAST(x1, x0, 9);   \
  } while (0)

/* 256-bit permutation four-interleaved */
#define perm256x4(x0_0, x1_0, x0_1, x1_1, x0_2, x1_2, x0_3, x1_3) \
  do {                                                            \
    R256_FIRST(x0_0, x1_0, 0);                                    \
    R256_FIRST(x0_1, x1_1, 0);                                    \
    R256_FIRST(x0_2, x1_2, 0);                                    \
    R256_FIRST(x0_3, x1_3, 0);                                    \
    R256_MIDDLE(x1_0, x0_0, 1);                                   \
    R256_MIDDLE(x1_1, x0_1, 1);                                   \
    R256_MIDDLE(x1_2, x0_2, 1);                                   \
    R256_MIDDLE(x1_3, x0_3, 1);                                   \
    R256_MIDDLE(x0_0, x1_0, 2);                                   \
    R256_MIDDLE(x0_1, x1_1, 2);                                   \
    R256_MIDDLE(x0_2, x1_2, 2);                                   \
    R256_MIDDLE(x0_3, x1_3, 2);                                   \
    R256_MIDDLE(x1_0, x0_0, 3);                                   \
    R256_MIDDLE(x1_1, x0_1, 3);                                   \
    R256_MIDDLE(x1_2, x0_2, 3);                                   \
    R256_MIDDLE(x1_3, x0_3, 3);                                   \
    R256_MIDDLE(x0_0, x1_0, 4);                                   \
    R256_MIDDLE(x0_1, x1_1, 4);                                   \
    R256_MIDDLE(x0_2, x1_2, 4);                                   \
    R256_MIDDLE(x0_3, x1_3, 4);                                   \
    R256_MIDDLE(x1_0, x0_0, 5);                                   \
    R256_MIDDLE(x1_1, x0_1, 5);                                   \
    R256_MIDDLE(x1_2, x0_2, 5);                                   \
    R256_MIDDLE(x1_3, x0_3, 5);                                   \
    R256_MIDDLE(x0_0, x1_0, 6);                                   \
    R256_MIDDLE(x0_1, x1_1, 6);                                   \
    R256_MIDDLE(x0_2, x1_2, 6);                                   \
    R256_MIDDLE(x0_3, x1_3, 6);                                   \
    R256_MIDDLE(x1_0, x0_0, 7);                                   \
    R256_MIDDLE(x1_1, x0_1, 7);                                   \
    R256_MIDDLE(x1_2, x0_2, 7);                                   \
    R256_MIDDLE(x1_3, x0_3, 7);                                   \
    R256_MIDDLE(x0_0, x1_0, 8);                                   \
    R256_MIDDLE(x0_1, x1_1, 8);                                   \
    R256_MIDDLE(x0_2, x1_2, 8);                                   \
    R256_MIDDLE(x0_3, x1_3, 8);                                   \
    R256_LAST(x1_0, x0_0, 9);                                     \
    R256_LAST(x1_1, x0_1, 9);                                     \
    R256_LAST(x1_2, x0_2, 9);                                     \
    R256_LAST(x1_3, x0_3, 9);                                     \
  } while (0)

/* Inversed Round Function for the 256-bit permutation */
#define Inv_R256_FIRST(x0, x1, i)         \
  do {                                    \
    x0 = A4(x0, RC0);                     \
    x1 = A4(A1(A1(x0, RC0), RC1(i)), x1); \
  } while (0)
#define Inv_R256_MIDDLE(x0, x1, i)        \
  do {                                    \
    x1 = A4(A1(A1(x0, RC0), RC1(i)), x1); \
  } while (0)
#define Inv_R256_LAST(x0, x1, i)           \
  do {                                     \
    x1 = XOR(A1(A1(x0, RC0), RC1(i)), x1); \
  } while (0)

/* Inversed 256-bit permutation */
#define Inv_perm256(x0, x1)     \
  do {                          \
    Inv_R256_FIRST(x1, x0, 9);  \
    Inv_R256_MIDDLE(x0, x1, 8); \
    Inv_R256_MIDDLE(x1, x0, 7); \
    Inv_R256_MIDDLE(x0, x1, 6); \
    Inv_R256_MIDDLE(x1, x0, 5); \
    Inv_R256_MIDDLE(x0, x1, 4); \
    Inv_R256_MIDDLE(x1, x0, 3); \
    Inv_R256_MIDDLE(x0, x1, 2); \
    Inv_R256_MIDDLE(x1, x0, 1); \
    Inv_R256_LAST(x0, x1, 0);   \
  } while (0)

/* Round Function for the 512-bit permutation */
#define R512_FIRST(x0, x1, x2, x3, i) \
  do {                                \
    x1 = A2(A1(x0, RC0), x1);         \
    x3 = A2(A1(x2, RC0), x3);         \
    x0 = A2(x0, RC0);                 \
    x2 = A1(A2(x2, RC0), RC1(i));     \
  } while (0)
#define R512_MIDDLE(x0, x1, x2, x3, i) \
  do {                                 \
    x1 = A2(A1(x0, RC0), x1);          \
    x3 = A2(A3(x2), x3);               \
    x2 = A1(x2, RC1(i));               \
  } while (0)
#define R512_LAST(x0, x1, x2, x3, i) \
  do {                               \
    x1 = XOR(A3(x0), x1);            \
    x3 = XOR(A3(x2), x3);            \
    x2 = A1(x2, RC1(i));             \
  } while (0)

/* 512-bit permutation */
#define perm512(x0, x1, x2, x3)      \
  do {                               \
    R512_FIRST(x0, x1, x2, x3, 0);   \
    R512_MIDDLE(x3, x0, x1, x2, 1);  \
    R512_MIDDLE(x2, x3, x0, x1, 2);  \
    R512_MIDDLE(x1, x2, x3, x0, 3);  \
    R512_MIDDLE(x0, x1, x2, x3, 4);  \
    R512_MIDDLE(x3, x0, x1, x2, 5);  \
    R512_MIDDLE(x2, x3, x0, x1, 6);  \
    R512_MIDDLE(x1, x2, x3, x0, 7);  \
    R512_MIDDLE(x0, x1, x2, x3, 8);  \
    R512_MIDDLE(x3, x0, x1, x2, 9);  \
    R512_MIDDLE(x2, x3, x0, x1, 10); \
    R512_MIDDLE(x1, x2, x3, x0, 11); \
    R512_MIDDLE(x0, x1, x2, x3, 12); \
    R512_MIDDLE(x3, x0, x1, x2, 13); \
    R512_LAST(x2, x3, x0, x1, 14);   \
  } while (0)

#endif  // __ARM_NEON

#endif  // AREION_NEON_H