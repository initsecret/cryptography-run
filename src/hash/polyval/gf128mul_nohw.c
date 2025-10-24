// Adapted from
// https://github.com/Shay-Gueron/AES-GCM-SIV/blob/04b984190fbaf31a31c02ad0cce350a957f48e36/AES_GCM_SIV_128/AES_GCM_SIV_128_Reference_Code/GCM_SIV_c.c

/*
###############################################################################
# AES-GCM-SIV developers and authors:                                         #
#                                                                             #
# Shay Gueron,    University of Haifa, Israel and                             #
#                 Intel Corporation, Israel Development Center, Haifa, Israel #
# Adam Langley,   Google                                                      #
# Yehuda Lindell, Bar Ilan University                                         #
###############################################################################
#                                                                             #
# References:                                                                 #
#                                                                             #
# [1] S. Gueron, Y. Lindell, GCM-SIV: Full Nonce Misuse-Resistant             #
# Authenticated Encryption at Under One Cycle per Byte,                       #
# 22nd ACM Conference on Computer and Communications Security,                #
# 22nd ACM CCS: pages 109-119, 2015.                                          #
# [2] S. Gueron, A. Langley, Y. Lindell, AES-GCM-SIV: Nonce Misuse-Resistant  #
# Authenticated Encryption.                                                   #
# https://tools.ietf.org/html/draft-gueron-gcmsiv-02#                         #
###############################################################################
#                                                                             #
###############################################################################
#                                                                             #
# Copyright (c) 2016, Shay Gueron                                             #
#                                                                             #
#                                                                             #
# Permission to use this code for AES-GCM-SIV is granted.                     #
#                                                                             #
# Redistribution and use in source and binary forms, with or without          #
# modification, are permitted provided that the following conditions are      #
# met:                                                                        #
#                                                                             #
# * Redistributions of source code must retain the above copyright notice,    #
#   this list of conditions and the following disclaimer.                     #
#                                                                             #
# * Redistributions in binary form must reproduce the above copyright         #
#   notice, this list of conditions and the following disclaimer in the       #
#   documentation and/or other materials provided with the distribution.      #
#                                                                             #
# * The names of the contributors may not be used to endorse or promote       #
# products derived from this software without specific prior written          #
# permission.                                                                 #
#                                                                             #
###############################################################################
#                                                                             #
###############################################################################
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ""AS IS"" AND ANY                  #
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE           #
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR          #
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL INTEL CORPORATION OR              #
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,       #
# EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,         #
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR          #
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF      #
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING        #
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS          #
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.                #
###############################################################################
*/

#include <cryptography-run/base.h>

#include "polyval_internal.h"

// Does carryless multiplication src1*src2
// Stores the result in destination
void mul(uint64_t src1, uint64_t src2, uint64_t *dst) {
  bssl_gcm_mul64_nohw(&dst[0], &dst[1], src1, src2);
}

/** From
 * https://github.com/Shay-Gueron/AES-GCM-SIV/blob/04b984190fbaf31a31c02ad0cce350a957f48e36/AES_GCM_SIV_128/AES_GCM_SIV_128_Reference_Code/clmul_emulator.c#L96-L110
 */
void vclmul_emulator(const uint64_t *src1,
                     const uint64_t *src2,
                     uint64_t *destination,
                     uint8_t imm) {
  switch (imm) {
    case 0x00:
      mul(src1[0], src2[0], destination);
      break;
    case 0x01:
      mul(src1[1], src2[0], destination);
      break;
    case 0x10:
      mul(src1[0], src2[1], destination);
      break;
    case 0x11:
      mul(src1[1], src2[1], destination);
      break;
  }
}

/**
 * from
 * https://github.com/Shay-Gueron/AES-GCM-SIV/blob/04b984190fbaf31a31c02ad0cce350a957f48e36/AES_GCM_SIV_128/AES_GCM_SIV_128_Reference_Code/GCM_SIV_c.c#L186-L230
 */
void gfmul_int(const uint64_t *a, const uint64_t *b, uint64_t *res) {
  uint64_t tmp1[2], tmp2[2], tmp3[2], tmp4[2];
  uint64_t XMMMASK[2] = {0x1, 0xc200000000000000};

  vclmul_emulator(a, b, tmp1, 0x00);
  vclmul_emulator(a, b, tmp3, 0x10);
  vclmul_emulator(a, b, tmp2, 0x01);
  vclmul_emulator(a, b, tmp4, 0x11);

  tmp2[0] ^= tmp3[0];
  tmp2[1] ^= tmp3[1];

  tmp3[0] = 0;
  tmp3[1] = tmp2[0];

  tmp2[0] = tmp2[1];
  tmp2[1] = 0;

  tmp1[0] ^= tmp3[0];
  tmp1[1] ^= tmp3[1];

  tmp4[0] ^= tmp2[0];
  tmp4[1] ^= tmp2[1];

  vclmul_emulator(XMMMASK, tmp1, tmp2, 0x01);
  ((uint32_t *)tmp3)[0] = ((uint32_t *)tmp1)[2];
  ((uint32_t *)tmp3)[1] = ((uint32_t *)tmp1)[3];
  ((uint32_t *)tmp3)[2] = ((uint32_t *)tmp1)[0];
  ((uint32_t *)tmp3)[3] = ((uint32_t *)tmp1)[1];

  tmp1[0] = tmp2[0] ^ tmp3[0];
  tmp1[1] = tmp2[1] ^ tmp3[1];

  vclmul_emulator(XMMMASK, tmp1, tmp2, 0x01);
  ((uint32_t *)tmp3)[0] = ((uint32_t *)tmp1)[2];
  ((uint32_t *)tmp3)[1] = ((uint32_t *)tmp1)[3];
  ((uint32_t *)tmp3)[2] = ((uint32_t *)tmp1)[0];
  ((uint32_t *)tmp3)[3] = ((uint32_t *)tmp1)[1];

  tmp1[0] = tmp2[0] ^ tmp3[0];
  tmp1[1] = tmp2[1] ^ tmp3[1];

  res[0] = tmp4[0] ^ tmp1[0];
  res[1] = tmp4[1] ^ tmp1[1];
}
