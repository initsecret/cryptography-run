#ifndef CR_PERM_H
#define CR_PERM_H

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

// FIXME: support ARM
#ifdef __x86_64__

#include <wmmintrin.h>

#define PERM_MAX_STATE_LENGTH 128  // Simpira1024

// FIXME: Implement 2x and 4x APIs
// FIXME: make it an in-place API

// Permutation represents a public permutation.
typedef struct {
  /** name of scheme */
  char name[100];
  /** length of state in bytes */
  uint8_t state_len;

  /**
   * Permutes |in_state| forward and writes output to |out_state|.
   *
   * |in_state| and |out_state| MUST have length |Permutation.state_len|.
   *
   * |in_state| and |out_state| may be the same buffer.
   *
   * @return one on success and zero otherwise.
   */
  int (*forward)(uint8_t *in_state, uint8_t *out_state);

  /**
   * Permutes |in_state| backward and writes output to |out_state|.
   *
   * |in_state| and |out_state| MUST have length |Permutation.state_len|.
   *
   * |in_state| and |out_state| may be the same buffer.
   *
   * @return one on success and zero otherwise.
   */
  int (*backward)(uint8_t *in_state, uint8_t *out_state);
} Permutation;

const Permutation *Permutation_Simpira256();
const Permutation *Permutation_Simpira512();
const Permutation *Permutation_Simpira1024();
const Permutation *Permutation_RRBlake2b();
const Permutation *Permutation_Areion256();
const Permutation *Permutation_Areion512();

#endif  // __x86_64__

#ifdef __cplusplus
}
#endif

#endif  // CR_PERM_H