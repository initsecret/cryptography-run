#include <algorithm>
#include <cstdint>
#include "test-util.hpp"

#include <gtest/gtest.h>

#include <cryptography-run/aead.h>
#include <cryptography-run/axuhash.h>
#include <cryptography-run/hash.h>

class CrHashParamTests : public ::testing::TestWithParam<const Hash *> {};

TEST_P(CrHashParamTests, BasicCrHash) {
  auto h = GetParam();

  for (size_t msg_len :
       {0, 2, 4, 8, 16, 32, 48, 64, 80, 128, 256, 512, 1024, 16384}) {
    std::vector<uint8_t> key(h->key_len, 0x42);
    std::vector<uint8_t> msg(msg_len, 0x42);
    std::vector<uint8_t> digest(h->digest_len, 0xfa);
    std::vector<uint8_t> oneshot_digest(h->digest_len, 0xaf);

    HashState ctx;
    memset(&ctx, 0, sizeof(ctx));

    ASSERT_TRUE(h->init(&ctx, key.data(), key.size(), digest.size()));
    ASSERT_TRUE(h->update(&ctx, msg.data(), msg.size()));
    ASSERT_TRUE(h->final(&ctx, digest.data(), digest.size()));

    ASSERT_TRUE(h->keyed_hash(key.data(), key.size(), oneshot_digest.data(),
                              oneshot_digest.size(), msg.data(), msg.size()));
    ASSERT_EQ(BytesToHex(digest), BytesToHex(oneshot_digest))
        << "incremental digest does not match one-shot digest\nmsg_len: "
        << msg_len << "\nincremental digest : " << BytesToHex(digest)
        << "\none-shot digest : " << BytesToHex(oneshot_digest) << "\n";
  }
}

INSTANTIATE_TEST_SUITE_P(
    CrHashTest,
    CrHashParamTests,
    ::testing::Values(
#ifdef __x86_64__
        Hash_blake2b(),
        Hash_sha256(),
#endif
#ifdef CR_HAS_AREION
        Hash_Areion512Sponge(),
        Hash_ODAreion512(),
#endif
        Hash_ascon256(),
        Hash_Sparkle512Sponge(),
        Hash_sha3_256()),
    [](const testing::TestParamInfo<CrHashParamTests::ParamType> &info) {
      auto param = info.param;
      std::string name(param->name);
      std::replace(name.begin(), name.end(), '-', '_');
      return name;
    });

#ifdef __x86_64__

TEST(CrHashTest, Blake2bKAT) {
  // From blake2b.c
  // See src/hash/blake2b/COPYING
#include "blake2-kat.h"
  uint8_t key[BLAKE2B_KEYBYTES];
  uint8_t buf[BLAKE2_KAT_LENGTH];
  size_t i, step;

  for (i = 0; i < BLAKE2B_KEYBYTES; ++i)
    key[i] = (uint8_t)i;

  for (i = 0; i < BLAKE2_KAT_LENGTH; ++i)
    buf[i] = (uint8_t)i;

  // Test one-shot API
  for (i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
    uint8_t digest[BLAKE2B_OUTBYTES];
    Hash_blake2b()->keyed_hash(key, BLAKE2B_KEYBYTES, digest, BLAKE2B_OUTBYTES,
                               buf, i);
    ASSERT_EQ(memcmp(digest, blake2b_keyed_kat[i], BLAKE2B_OUTBYTES), 0);
  }

  // Test incremental API
  for (step = 1; step < BLAKE2B_BLOCKBYTES; ++step) {
    for (i = 0; i < BLAKE2_KAT_LENGTH; ++i) {
      uint8_t hash[BLAKE2B_OUTBYTES];
      HashState ctx;
      memset(&ctx, 0, sizeof(ctx));
      uint8_t *p = buf;
      size_t mlen = i;

      auto h = Hash_blake2b();
      ASSERT_TRUE(h->init(&ctx, key, BLAKE2B_KEYBYTES, BLAKE2B_OUTBYTES));
      while (mlen >= step) {
        ASSERT_TRUE(h->update(&ctx, p, step));
        mlen -= step;
        p += step;
      }
      ASSERT_TRUE(h->update(&ctx, p, mlen));
      ASSERT_TRUE(h->final(&ctx, hash, BLAKE2B_OUTBYTES));

      int res = (0 == memcmp(hash, blake2b_keyed_kat[i], BLAKE2B_OUTBYTES));
      ASSERT_TRUE(res);
    }
  }
}

TEST(CrHashTest, Sha256KAT) {
  // KATs from
  // https://cs.opensource.google/go/go/+/master:src/crypto/sha256/sha256_test.go;l=27;drc=651e839df81efd6b6cc26d8a11e51b8ec990127c
  std::map<std::string, std::string> out_in{
      {"4f9b189a13d030838269dce846b16a1ce9ce81fe63e65de2f636863336a98fe6",
       "How can you write a big system without C++?  -Paul Glick"},
      {"61c0cc4c4bd8406d5120b3fb4ebc31ce87667c162f29468b3c779675a85aebce",
       "C is as portable as Stonehedge!!"}};
  for (const auto &[outstr, instr] : out_in) {
    auto expected = BytesFromHex(outstr);
    auto in = BytesFromChar(instr);

    auto got = BytesFromHex(
        "0000000000000000000000000000000000000000000000000000000000000000");
    auto h = Hash_sha256();

    int res = h->hash(got.data(), got.size(), in.data(), in.size());
    ASSERT_TRUE(res) << "hashing failed";
    ASSERT_EQ(expected, got) << "hashing failed to produce expected output";

    // Test incremental
    got = BytesFromHex(
        "0000000000000000000000000000000000000000000000000000000000000000");
    HashState hash_ctx;
    res &= h->init(&hash_ctx, nullptr, 0, 32);
    res &= h->update(&hash_ctx, in.data(), in.size());
    res &= h->final(&hash_ctx, got.data(), got.size());
    ASSERT_TRUE(res) << "hashing failed";
    ASSERT_EQ(expected, got) << "hashing failed to produce expected output";

    // Test keyed
    got = BytesFromHex(
        "0000000000000000000000000000000000000000000000000000000000000000");
    res &= h->init(&hash_ctx, in.data(), in.size(), 32);
    res &= h->final(&hash_ctx, got.data(), got.size());
    ASSERT_TRUE(res) << "hashing failed";
    ASSERT_EQ(expected, got) << "hashing failed to produce expected output";
  }
}

#endif
