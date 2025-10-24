#ifndef CR_AEAD_BENCHES_HPP
#define CR_AEAD_BENCHES_HPP

#include <cstddef>
#include <string>

#include <cryptography-run/aead.h>
#include <sys/random.h>

#include "benches.hpp"
#include "timing.hpp"

using std::size_t;

/* whether to bench additional schemes */
#define AEAD_BENCH_EXTRA true

/** number of times to repeat AEAD measurments */
const auto AEAD_REPEAT = 4;

/** bytes of AD in TLS 1.2 */
static const size_t kTLSADLen = 13;

/** default schemes for log and linear benchmarks */
const std::vector<const Aead *> defaultSchemes{
    Aead_bssl_aes256_gcm(),
    Aead_bssl_chapoly(),
    Aead_shake128(),
    Aead_turboshake128(),
#ifdef CR_HAS_AREION
    Aead_och_s_areion(),
    Aead_och_p_areion(),
    Aead_OCSimple256_512_S_Areion(),
    Aead_OCSimple256_512_P_Areion(),
#endif
#if (AEAD_BENCH_EXTRA == true)
    Aead_bssl_aes128_gcm(),
    Aead_bssl_xchapoly(),
    Aead_ascon128(),
    Aead_aegis256(),
    Aead_aes128_ocb3(),
    Aead_och_s_sparkle(),
    Aead_och_p_sparkle(),
#endif
#if (AEAD_BENCH_EXTRA == true) && defined(__x86_64__)
    Aead_blake2b_opp_mem(),
    Aead_aes256_gcm(),
    Aead_cty_areion512sponge_aes256_gcm(),
    Aead_xth_areion512sponge_aes256_gcm(),
    Aead_cty_sha256_aes256_gcm(),
    Aead_xth_sha256_aes256_gcm(),
#endif
};

class AeadBench {
 public:
  std::string benchname;
  std::vector<AeadOperation> operations;
  const std::vector<const Aead *> schemes;
  std::vector<std::tuple<size_t, size_t>> msg_ad_lens;
};

static std::vector<AeadBench> aead_benches{
    {
        "log",
        {
            AeadOperation::hot_seal_rand_nonce,
            AeadOperation::cold_seal_rand_nonce,
            AeadOperation::hot_seal_seq_nonce,
            AeadOperation::hot_open,
        },
        defaultSchemes,
        {
            {2, kTLSADLen},
            {4, kTLSADLen},
            {8, kTLSADLen},
            {16, kTLSADLen},
            {32, kTLSADLen},
            {64, kTLSADLen},
            {128, kTLSADLen},
            {256, kTLSADLen},
            {512, kTLSADLen},
            {1024, kTLSADLen},
            {2048, kTLSADLen},
            {4096, kTLSADLen},
            {8192, kTLSADLen},
            {16384, kTLSADLen},
            {32768, kTLSADLen},
            {65536, kTLSADLen},
            {131072, kTLSADLen},
        },
    },
    {
        "linear",
        {
            AeadOperation::hot_seal_rand_nonce,
            AeadOperation::cold_seal_rand_nonce,
            AeadOperation::hot_seal_seq_nonce,
            AeadOperation::hot_open,
        },
        defaultSchemes,
        {{0, kTLSADLen},
         {64, kTLSADLen},
         {128, kTLSADLen},
         {192, kTLSADLen},
         {256, kTLSADLen},
         {320, kTLSADLen},
         {384, kTLSADLen},
         {448, kTLSADLen},
         {512, kTLSADLen},
         {576, kTLSADLen},
         {640, kTLSADLen},
         {704, kTLSADLen},
         {768, kTLSADLen},
         {832, kTLSADLen},
         {896, kTLSADLen},
         {960, kTLSADLen},
         {1024, kTLSADLen}},
    },
// XtH Graph
#ifdef __x86_64__
    {
        "xth",
        {
            AeadOperation::hot_seal_rand_nonce,
        },
        {
            Aead_aes256_gcm(),
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
        },
        {{16, 0},
         {16, 16},
         {16, 32},
         {16, 48},
         {16, 64},
         {16, 80},
         {16, 96},
         {16, 112},
         {16, 128},
         {16, 144},
         {16, 160},
         {16, 176},
         {16, 192},
         {16, 208},
         {16, 224},
         {16, 240},
         {16, 256}},
    },
#endif
};

static std::vector<AeadBench> quick_aead_benches{
    {
        "quick",
        {
            AeadOperation::hot_seal_rand_nonce,
            AeadOperation::cold_seal_rand_nonce,
            AeadOperation::hot_seal_seq_nonce,
            AeadOperation::hot_open,
        },
        {
            // Aead_bssl_aes128_gcm(),
            // Aead_bssl_chapoly(),
            Aead_och_s_areion(), Aead_och_p_areion(), Aead_ocs_s_areion(),
            Aead_ocs_p_areion(),
            // Aead_OCSimple256_512_S_Areion(),
            // Aead_OCSimple256_512_P_Areion(),
        },
        {
            {32, 32},
        },
    },
};

#define SpeedWithRetry(speed_fn_name)                                         \
  static bool speed_fn_name##WithRetry(const AeadOperation op, const Aead *a, \
                                       size_t msg_len, size_t ad_len) {       \
    AttemptWithRetry(speed_fn_name(op, a, msg_len, ad_len));                  \
  }

#define setUpAead()                                     \
  std::string name = a->name;                           \
  std::vector<uint8_t> key(a->key_len, 0x42);           \
  std::vector<uint8_t> pubnonce(a->pubnonce_len, 0x42); \
  std::vector<uint8_t> secnonce(a->secnonce_len, 0x42); \
  std::vector<uint8_t> ad(ad_len, 0x42);                \
  std::vector<uint8_t> msg(msg_len, 0x42);              \
  std::vector<uint8_t> ct(msg_len + a->overhead, 0x00); \
  AeadKey ctx;                                          \
  memset(&ctx, 0, sizeof(ctx));

#define measureFunc(func)                                               \
  TimeResults results;                                                  \
  if (!TimeFunction(&results, func)) {                                  \
    fprintf(stderr, "Failed %s with AEAD %s.\n", to_string(op).c_str(), \
            a->name);                                                   \
    return false;                                                       \
  }                                                                     \
  if (!results.IsReasonable(msg_len, ad_len)) {                         \
    return false;                                                       \
  }                                                                     \
  results.PrintAead(name, op, msg_len, ad_len);                         \
  return true;

static bool SpeedAeadHotOpen(const AeadOperation op,
                             const Aead *a,
                             size_t msg_len,
                             size_t ad_len) {
  if (op != AeadOperation::hot_open) {
    fprintf(stderr, "unexpected operation: %s", to_string(op).c_str());
    return false;
  }

  setUpAead();
  if (!(a->init(&ctx, key.data(), key.size()))) {
    fprintf(stderr, "Failed to initialize AEAD: %s.\n", a->name);
    return false;
  }

  std::vector<uint8_t> dec(msg_len + a->overhead, 0x00);
  std::vector<uint8_t> dec_secnonce(a->secnonce_len, 0x00);

  if (!(a->seal(&ctx, ct.data(), msg.data(), msg_len, ad.data(), ad_len,
                pubnonce.data(), secnonce.data()))) {
    fprintf(stderr, "Failed to seal with AEAD: %s.\n", a->name);
    return false;
  }

  auto func = [&a, msg_len, ad_len, &ctx, &dec, &dec_secnonce, &ct, &ad,
               &pubnonce]() -> bool {
    int ret = 1;
    ret &= a->open(&ctx, dec.data(), dec_secnonce.data(), ct.data(), ct.size(),
                   ad.data(), ad_len, pubnonce.data());
    return (ret == 1);
  };
  measureFunc(func);
}
SpeedWithRetry(SpeedAeadHotOpen);

static bool SpeedAeadHotSealRandNonce(const AeadOperation op,
                                      const Aead *a,
                                      size_t msg_len,
                                      size_t ad_len) {
  if (op != AeadOperation::hot_seal_rand_nonce) {
    fprintf(stderr, "unexpected operation: %s", to_string(op).c_str());
    return false;
  }

  setUpAead();
  if (!(a->init(&ctx, key.data(), key.size()))) {
    fprintf(stderr, "Failed to initialize AEAD: %s.\n", a->name);
    return false;
  }

  auto func = [&a, msg_len, ad_len, &ctx, &ct, &msg, &ad, &pubnonce,
               &secnonce]() -> bool {
    int ret = 1;
    ret &= RANDOM_BYTES(pubnonce.data(), pubnonce.size());
    ret &= RANDOM_BYTES(secnonce.data(), secnonce.size());
    ret &= a->seal(&ctx, ct.data(), msg.data(), msg_len, ad.data(), ad_len,
                   pubnonce.data(), secnonce.data());
    return (ret == 1);
  };
  measureFunc(func);
}
SpeedWithRetry(SpeedAeadHotSealRandNonce);

static bool SpeedAeadHotSealSeqNonce(const AeadOperation op,
                                     const Aead *a,
                                     size_t msg_len,
                                     size_t ad_len) {
  if (op != AeadOperation::hot_seal_seq_nonce) {
    fprintf(stderr, "unexpected operation: %s", to_string(op).c_str());
    return false;
  }

  setUpAead();
  if (!(a->init(&ctx, key.data(), key.size()))) {
    fprintf(stderr, "Failed to initialize AEAD: %s.\n", a->name);
    return false;
  }

  if (secnonce.size() > 0) {
    /* If there's a secnonce, then increment the last byte of the secnonce */
    secnonce[secnonce.size() - 1] = 0;
  } else {
    /* Otherwise, we increment the last byte of the pubnonce */
    pubnonce[pubnonce.size() - 1] = 0;
  }

  auto func = [&a, msg_len, ad_len, &ctx, &ct, &msg, &ad, &pubnonce,
               &secnonce]() -> bool {
    int ret = 1;
    if (secnonce.size() > 0) {
      secnonce[secnonce.size() - 1] += 1;
    } else {
      pubnonce[pubnonce.size() - 1] += 1;
    }
    ret &= a->seal(&ctx, ct.data(), msg.data(), msg_len, ad.data(), ad_len,
                   pubnonce.data(), secnonce.data());
    return (ret == 1);
  };
  measureFunc(func);
}
SpeedWithRetry(SpeedAeadHotSealSeqNonce);

static bool SpeedAeadColdSealRandNonce(const AeadOperation op,
                                       const Aead *a,
                                       size_t msg_len,
                                       size_t ad_len) {
  if (op != AeadOperation::cold_seal_rand_nonce) {
    fprintf(stderr, "unexpected operation: %s", to_string(op).c_str());
    return false;
  }

  setUpAead();
  if (!(a->init(&ctx, key.data(), key.size()))) {
    fprintf(stderr, "Failed to initialize AEAD: %s.\n", a->name);
    return false;
  }

  auto func = [&a, msg_len, ad_len, &ctx, &key, &ct, &msg, &ad, &pubnonce,
               &secnonce]() -> bool {
    int ret = 1;

    memset(&ctx, 0, sizeof(ctx));
    ret &= RANDOM_BYTES(key.data(), key.size());
    ret &= a->init(&ctx, key.data(), key.size());

    ret &= RANDOM_BYTES(pubnonce.data(), pubnonce.size());
    ret &= RANDOM_BYTES(secnonce.data(), secnonce.size());
    ret &= a->seal(&ctx, ct.data(), msg.data(), msg_len, ad.data(), ad_len,
                   pubnonce.data(), secnonce.data());
    return (ret == 1);
  };
  measureFunc(func);
}
SpeedWithRetry(SpeedAeadColdSealRandNonce);

static bool SpeedAEADEncrypt(AeadOperation op,
                             const Aead *a,
                             size_t msg_len,
                             size_t ad_len) {
  bool retried = false;
  for (int i = 0; i < MAX_RETRY; i++) {
    std::string name = a->name;

    std::vector<uint8_t> key(a->key_len, 0x42);
    std::vector<uint8_t> pubnonce(a->pubnonce_len, 0x42);
    std::vector<uint8_t> secnonce(a->secnonce_len, 0x42);
    std::vector<uint8_t> ad(ad_len, 0x42);
    std::vector<uint8_t> msg(msg_len, 0x42);
    std::vector<uint8_t> ct(msg_len + a->overhead, 0x00);

    AeadKey ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (!(a->init(&ctx, key.data(), key.size()))) {
      fprintf(stderr, "Failed to initialize AEAD: %s.\n", a->name);
      return false;
    }

    TimeResults hotSealResults;
    if (!TimeFunction(&hotSealResults,
                      [&a, msg_len, ad_len, &ctx, &ct, &msg, &ad, &pubnonce,
                       &secnonce]() -> bool {
                        int ret = 1;
                        ret &= RANDOM_BYTES(pubnonce.data(), pubnonce.size());
                        ret &= RANDOM_BYTES(secnonce.data(), secnonce.size());
                        ret &= a->seal(&ctx, ct.data(), msg.data(), msg_len,
                                       ad.data(), ad_len, pubnonce.data(),
                                       secnonce.data());
                        return (ret == 1);
                      })) {
      fprintf(stderr, "Failed to hot seal with AEAD: %s.\n", a->name);
      return false;
    }
    if (!hotSealResults.IsReasonable(msg_len, ad_len)) {
      retried = true;
      continue;
    }

    memset(pubnonce.data(), 0x00, pubnonce.size());
    memset(secnonce.data(), 0x00, secnonce.size());
    if (secnonce.size() > 0) {
      RANDOM_BYTES(pubnonce.data(), pubnonce.size());
    }
    TimeResults hotSeqNonceSealResults;
    if (!TimeFunction(&hotSeqNonceSealResults,
                      [&a, msg_len, ad_len, &ctx, &ct, &msg, &ad, &pubnonce,
                       &secnonce]() -> bool {
                        int ret = 1;
                        if (secnonce.size() > 0) {
                          secnonce[secnonce.size() - 1] += 1;
                        } else {
                          pubnonce[pubnonce.size() - 1] += 1;
                        }
                        ret &= a->seal(&ctx, ct.data(), msg.data(), msg_len,
                                       ad.data(), ad_len, pubnonce.data(),
                                       secnonce.data());
                        return (ret == 1);
                      })) {
      fprintf(stderr, "Failed to hot sequential seal with AEAD: %s.\n",
              a->name);
      return false;
    }
    if (!hotSeqNonceSealResults.IsReasonable(msg_len, ad_len)) {
      retried = true;
      continue;
    }

    TimeResults coldSealResults;
    if (!TimeFunction(&coldSealResults,
                      [&a, msg_len, ad_len, &ctx, &key, &ct, &msg, &ad,
                       &pubnonce, &secnonce]() -> bool {
                        int ret = 1;
                        memset(&ctx, 0, sizeof(ctx));
                        ret &= RANDOM_BYTES(key.data(), key.size());
                        ret &= RANDOM_BYTES(pubnonce.data(), pubnonce.size());
                        ret &= RANDOM_BYTES(secnonce.data(), secnonce.size());

                        ret &= a->init(&ctx, key.data(), key.size());
                        ret &= a->seal(&ctx, ct.data(), msg.data(), msg_len,
                                       ad.data(), ad_len, pubnonce.data(),
                                       secnonce.data());
                        return (ret == 1);
                      })) {
      fprintf(stderr, "Failed to cold seal with AEAD: %s.\n", a->name);
      return false;
    }
    if (!coldSealResults.IsReasonable(msg_len, ad_len)) {
      retried = true;
      continue;
    }

    hotSealResults.PrintAead(name, op, msg_len, ad_len);
    hotSeqNonceSealResults.PrintAead(name, op, msg_len, ad_len);
    coldSealResults.PrintAead(name, op, msg_len, ad_len);
    if (retried) {
      fprintf(stderr, "got reasonable cycles per byte on retry!!\n");
    }
    return true;
  }
  fprintf(stderr, "Exceeded max retries for %s at (%lu, %lu).\n", a->name,
          msg_len, ad_len);
  return false;
}

static bool SpeedAeadBench(AeadBench const &bench) {
  for (const auto op : bench.operations) {
    for (const auto a : bench.schemes) {
      for (const auto &[msg_len, ad_len] : bench.msg_ad_lens) {
        if (op == AeadOperation::hot_seal_rand_nonce) {
          if (!SpeedAeadHotSealRandNonceWithRetry(op, a, msg_len, ad_len)) {
            return false;
          }
        } else if (op == AeadOperation::hot_seal_seq_nonce) {
          if (!SpeedAeadHotSealSeqNonceWithRetry(op, a, msg_len, ad_len)) {
            return false;
          }
        } else if (op == AeadOperation::cold_seal_rand_nonce) {
          if (!SpeedAeadColdSealRandNonceWithRetry(op, a, msg_len, ad_len)) {
            return false;
          }
        } else if (op == AeadOperation::hot_open) {
          if ((std::string(a->name) != "Aead-TurboSHAKE128") &&
              (std::string(a->name) != "Aead-SHAKE128")) {
            if (!SpeedAeadHotOpenWithRetry(op, a, msg_len, ad_len)) {
              return false;
            }
          }
        } else {
          fprintf(stderr, "Unrecognized AeadOperation: %s\n",
                  to_string(op).c_str());
          return false;
        }
      }
    }
  }
  return true;
}

#endif  // CR_AEAD_BENCHES_HPP
