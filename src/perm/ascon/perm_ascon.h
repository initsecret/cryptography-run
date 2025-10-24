#ifndef CR_PERM_ASCON_H
#define CR_PERM_ASCON_H

#include <stdint.h>

typedef union {
  uint64_t x[5];
  uint32_t w[5][2];
  uint8_t b[5][8];
} ascon_state_t;

// Ascon round constants
#define RC0 0xf0
#define RC1 0xe1
#define RC2 0xd2
#define RC3 0xc3
#define RC4 0xb4
#define RC5 0xa5
#define RC6 0x96
#define RC7 0x87
#define RC8 0x78
#define RC9 0x69
#define RCa 0x5a
#define RCb 0x4b

#define RC(i) (i)

uint64_t ROR(uint64_t x, int n) {
  return x >> n | x << (-n & 63);
}

void ROUND(ascon_state_t *s, uint8_t C) {
  ascon_state_t t;
  /* round constant */
  s->x[2] ^= C;
  /* s-box layer */
  s->x[0] ^= s->x[4];
  s->x[4] ^= s->x[3];
  s->x[2] ^= s->x[1];
  t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
  t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
  t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);
  t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
  t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
  t.x[1] ^= t.x[0];
  t.x[3] ^= t.x[2];
  t.x[0] ^= t.x[4];
  /* linear layer */
  s->x[2] = t.x[2] ^ ROR(t.x[2], 6 - 1);
  s->x[3] = t.x[3] ^ ROR(t.x[3], 17 - 10);
  s->x[4] = t.x[4] ^ ROR(t.x[4], 41 - 7);
  s->x[0] = t.x[0] ^ ROR(t.x[0], 28 - 19);
  s->x[1] = t.x[1] ^ ROR(t.x[1], 61 - 39);
  s->x[2] = t.x[2] ^ ROR(s->x[2], 1);
  s->x[3] = t.x[3] ^ ROR(s->x[3], 10);
  s->x[4] = t.x[4] ^ ROR(s->x[4], 7);
  s->x[0] = t.x[0] ^ ROR(s->x[0], 19);
  s->x[1] = t.x[1] ^ ROR(s->x[1], 39);
  s->x[2] = ~s->x[2];
}

// Ascon is 320 bits (40 bytes) wide, and comes in a 6-round variant and a
// 12-round variant. Ascon-Hash256 uses only the 12-round variant, while
// Ascon-AEAD128 uses the 12-round variant for initialization and finalization
// and uses the 8-round variant for intermediate duplex processing (ie
// processing ad and msg.)
// https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/round-2/spec-doc-rnd2/ascon-spec-round2.pdf
static const uint8_t perm_ascon_state_len = 40;

void perm_ascon12_forward(ascon_state_t *s) {
  ROUND(s, RC0);
  ROUND(s, RC1);
  ROUND(s, RC2);
  ROUND(s, RC3);
  ROUND(s, RC4);
  ROUND(s, RC5);
  ROUND(s, RC6);
  ROUND(s, RC7);
  ROUND(s, RC8);
  ROUND(s, RC9);
  ROUND(s, RCa);
  ROUND(s, RCb);
}

void perm_ascon6_forward(ascon_state_t *s) {
  ROUND(s, RC6);
  ROUND(s, RC7);
  ROUND(s, RC8);
  ROUND(s, RC9);
  ROUND(s, RCa);
  ROUND(s, RCb);
}

#endif /* CR_PERM_ASCON_H */
