#ifndef CR_AEAD_H
#define CR_AEAD_H

#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>

#include "base.h"

#if defined(__cplusplus)
extern "C" {
#endif

#define AEAD_MAX_KEY_LENGTH 48       // AEZ
#define AEAD_MAX_PUBNONCE_LENGTH 32  // OCH-P
#define AEAD_MAX_SECNONCE_LENGTH 32  // OCH-S
#define AEAD_MAX_OVERHEAD 64         // OCH-S

#define AEAD_MAX_CTX_SIZE 2000  // OCH

/**
 * AeadKey represents a processed AEAD key.
 */
typedef struct {
  alignas(32) uint8_t opaque[AEAD_MAX_CTX_SIZE];
} AeadKey;

/**
 * Aead represents an AEAD scheme.
 */
typedef struct {
  /** name of scheme */
  char name[100];
  /** length of key in bytes */
  uint8_t key_len;
  /** length of public nonce in bytes */
  uint8_t pubnonce_len;
  /** length of secret nonce in bytes */
  uint8_t secnonce_len;
  /** ciphertext overhead in bytes
   *  for tag-based schemes, this is tag_len + secnonce_len */
  uint8_t overhead;

  /**
   * Initalizes AeadKey |aead_key| with |key|.
   *
   * |raw_key| MUST be |Aead.key_len| bytes or some other supported length.
   *
   * @return one on success and zero otherwise.
   */
  int (*init)(AeadKey *aead_key, const uint8_t *key, size_t key_len);

  /**
   * Seals |msg| with |ad| and writes the ciphertext to |ct|.
   *
   * At most |msg_len| + |Aead.overhead| bytes are written to |ct|.
   *
   * |aead_key| MUST be initialized.
   *
   * |pubnonce| MUST be |Aead.pubnonce_len| bytes long.
   * |secnonce| MUST be |Aead.secnonce_len| bytes long.
   *
   * |msg| and |ct| may be the same buffer.
   *
   * @return one on success and zero otherwise.
   */
  int (*seal)(AeadKey *aead_key,
              uint8_t *ct,
              const uint8_t *msg,
              size_t msg_len,
              const uint8_t *ad,
              size_t ad_len,
              const uint8_t *pubnonce,
              const uint8_t *secnonce);

  /**
   * Opens |ct| with |ad| and writes the plaintext to |msg|.
   *
   * At most |ct_len| - |Aead.overhead| bytes are written to |msg|.
   *
   * At most |Aead.secnonce_len| bytes are written to |secnonce|.
   *
   * |pubnonce| MUST be |Aead.pubnonce_len| bytes long.
   *
   * |msg| and |ct| may be the same buffer.
   *
   * @return one on success and zero otherwise.
   */
  int (*open)(AeadKey *aead_key,
              uint8_t *msg,
              uint8_t *secnonce,
              const uint8_t *ct,
              size_t ct_len,
              const uint8_t *ad,
              size_t ad_len,
              const uint8_t *pubnonce);

  /**
   * Seals |msg| with |ad| and writes the ciphertext to |ct| and tag to |tag|.
   *
   * At most |msg_len| bytes are written to |ct|.
   *
   * At most |Aead.overhead| bytes are written to |tag|.
   *
   * |aead_key| MUST be initialized.
   *
   * |pubnonce| MUST be |Aead.pubnonce_len| bytes long.
   * |secnonce| MUST be |Aead.secnonce_len| bytes long.
   *
   * |msg| and |ct| may be the same buffer.
   *
   * @return one on success and zero otherwise.
   */
  int (*seal_scatter)(AeadKey *aead_key,
                      uint8_t *ctcore,
                      uint8_t *tag,
                      const uint8_t *msg,
                      size_t msg_len,
                      const uint8_t *ad,
                      size_t ad_len,
                      const uint8_t *pubnonce,
                      const uint8_t *secnonce);

  /**
   * Opens |ct| with |ad| and writes the plaintext to |msg| and the tag to
   * |tag|.
   *
   * At most |ct_len| - |Aead.overhead| bytes are written to |msg|.
   *
   * At most |Aead.secnonce_len| bytes are written to |secnonce|.
   *
   * At most |Aead.overhead| bytes are written to |out_tag|.
   *
   * |pubnonce| MUST be |Aead.pubnonce_len| bytes long.
   *
   * |msg| and |ct| may be the same buffer.
   *
   * @return one on success and zero otherwise.
   */
  int (*partial_open)(AeadKey *aead_key,
                      uint8_t *msg,
                      uint8_t *secnonce,
                      uint8_t *out_tag,
                      const uint8_t *ctcore,
                      size_t ctcore_len,
                      const uint8_t *ad,
                      size_t ad_len,
                      const uint8_t *pubnonce);
} Aead;

// BoringSSL
const Aead *Aead_bssl_aes128_gcm();
const Aead *Aead_bssl_aes256_gcm();
const Aead *Aead_bssl_chapoly();
const Aead *Aead_bssl_xchapoly();

// Ascon
const Aead *Aead_ascon128();

// XKCP
const Aead *Aead_turboshake128();
const Aead *Aead_shake128();

// libaegis
const Aead *Aead_aegis256();

// OCB3
const Aead *Aead_aes128_ocb3();

#ifdef __x86_64__
// Haberdashery
const Aead *Aead_aes256_gcm();

// Blake2b-OPP-MEM
const Aead *Aead_blake2b_opp_mem();

// CTY and XtH
const Aead *Aead_cty_sha256_aes256_gcm();
const Aead *Aead_xth_sha256_aes256_gcm();
const Aead *Aead_cty_blake2b_aes256_gcm();
const Aead *Aead_xth_blake2b_aes256_gcm();
const Aead *Aead_cty_ascon256_aes256_gcm();
const Aead *Aead_xth_ascon256_aes256_gcm();
const Aead *Aead_cty_sha3_256_aes256_gcm();
const Aead *Aead_xth_sha3_256_aes256_gcm();
const Aead *Aead_cty_areion512sponge_aes256_gcm();
const Aead *Aead_xth_areion512sponge_aes256_gcm();
#endif  // __x86_64__

// OCH
#ifdef CR_HAS_AREION
const Aead *Aead_och_s_areion();
const Aead *Aead_och_p_areion();
const Aead *Aead_ocs_s_areion();
const Aead *Aead_ocs_p_areion();
#endif
const Aead *Aead_och_s_sparkle();
const Aead *Aead_och_p_sparkle();

// OCSimple
#ifdef CR_HAS_AREION
const Aead *Aead_OCSimple256_512_S_Areion();
const Aead *Aead_OCSimple256_512_P_Areion();
#endif

#ifdef __cplusplus
}  // extern "C"

#include <vector>
namespace cr {
// FIXME: enable later
/** List of all AEAD schemes for testing and benchmarking */
static const std::vector<const Aead *> allAeads{
    // BoringSSL
    Aead_bssl_aes128_gcm(),
    Aead_bssl_aes256_gcm(),
    Aead_bssl_chapoly(),
    Aead_bssl_xchapoly(),
    // Ascon
    Aead_ascon128(),
    // XKCP
    Aead_shake128(),
    Aead_turboshake128(),
    // libaegis
    Aead_aegis256(),
    // OCB3
    Aead_aes128_ocb3(),
#ifdef __x86_64__
    // Haberdashery
    Aead_aes256_gcm(),
    // Blake2b-OPP-MEM
    Aead_blake2b_opp_mem(),
    // CTZ and XtH
    Aead_cty_sha256_aes256_gcm(),
    Aead_xth_sha256_aes256_gcm(),
    Aead_cty_blake2b_aes256_gcm(),
    Aead_xth_blake2b_aes256_gcm(),
    Aead_cty_ascon256_aes256_gcm(),
    Aead_xth_ascon256_aes256_gcm(),
    Aead_cty_sha3_256_aes256_gcm(),
    Aead_xth_sha3_256_aes256_gcm(),
    Aead_cty_areion512sponge_aes256_gcm(),
    Aead_xth_areion512sponge_aes256_gcm(),
#endif
// OCH
#ifdef CR_HAS_AREION
    Aead_och_s_areion(),
    Aead_och_p_areion(),
    Aead_ocs_s_areion(),
    Aead_ocs_p_areion(),
#endif
    Aead_och_s_sparkle(),
    Aead_och_p_sparkle(),
// OCSimple
#ifdef CR_HAS_AREION
    Aead_OCSimple256_512_S_Areion(),
    Aead_OCSimple256_512_P_Areion(),
#endif
};

}  // namespace cr
#endif

#endif  // CR_AEAD_H
