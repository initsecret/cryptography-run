#ifndef CR_POLYVAL_INTERNAL_H
#define CR_POLYVAL_INTERNAL_H

#include <cryptography-run/base.h>

#if defined(__cplusplus)
extern "C" {
#endif

void bssl_gcm_mul64_nohw(uint64_t *out_lo,
                         uint64_t *out_hi,
                         uint64_t a,
                         uint64_t b);

void gfmul_int(const uint64_t *a, const uint64_t *b, uint64_t *res);

#ifdef __cplusplus
}
#endif

#endif  // CR_POLYVAL_INTERNAL_H