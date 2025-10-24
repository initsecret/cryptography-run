#include <algorithm>
#include <cstdint>
#include <ostream>

#include "test-util.hpp"

#include <gtest/gtest.h>

#include <cryptography-run/aead.h>
#include <cryptography-run/axu.h>
#include <cryptography-run/base.h>
#include <cryptography-run/hash.h>
#include <cryptography-run/perm.h>

class AeadParamTests : public ::testing::TestWithParam<const Aead *> {};

TEST_P(AeadParamTests, BasicEncDec) {
  auto a = GetParam();

  for (size_t msg_len : {0, 2, 4, 8, 16, 32, 48, 64, 80, 108, 128, 144, 256,
                         304, 512, 1024, 16384}) {
    for (size_t ad_len : {0, 16, 32, 128, 144, 304, 320, 496, 512, 1024}) {
      std::vector<uint8_t> key(a->key_len, 0x42);
      std::vector<uint8_t> pubnonce(a->pubnonce_len, 0x42);
      std::vector<uint8_t> secnonce(a->secnonce_len, 0x24);
      std::vector<uint8_t> ad(ad_len, 0x42);
      std::vector<uint8_t> msg(msg_len, 0x42);
      std::vector<uint8_t> ct(msg_len + a->overhead, 0x00);
      std::vector<uint8_t> dec(msg_len, 0xfa);
      std::vector<uint8_t> dec_secnonce(a->secnonce_len, 0xab);

      AeadKey ctx;
      memset(&ctx, 0, sizeof(ctx));

      auto ct_len = msg_len + a->overhead;

      ASSERT_TRUE(a->init(&ctx, key.data(), key.size()));
      ASSERT_TRUE(a->seal(&ctx, ct.data(), msg.data(), msg_len, ad.data(),
                          ad_len, pubnonce.data(), secnonce.data()));
      if ((std::string(a->name) == "Aead-TurboSHAKE128") ||
          (std::string(a->name) == "Aead-SHAKE128")) {
        // these are fake AEADs
        continue;
      }
      if (msg.size() > 0) {
        ASSERT_NE(BytesToHex(ct.data(), msg.size()), BytesToHex(msg))
            << "encryption failed: ciphertext equals the message\nmsg_len: "
            << msg_len << "\nct_len : " << ct_len << "\n";
      }

      int res = a->open(&ctx, dec.data(), dec_secnonce.data(), ct.data(),
                        ct.size(), ad.data(), ad.size(), pubnonce.data());
      ASSERT_EQ(BytesToHex(dec), BytesToHex(msg))
          << "decryption failed: decrypted is not the message\nmsg_len: "
          << msg_len << "\nct_len : " << ct_len << "\nct : " << BytesToHex(ct)
          << "\n";
      ASSERT_EQ(BytesToHex(dec_secnonce), BytesToHex(secnonce))
          << "decryption failed: decrypted secret nonce is not the provided "
             "secret nonce\nmsg_len: "
          << msg_len << "\nct_len : " << ct_len << "\nct : " << BytesToHex(ct)
          << "\n";
      ASSERT_TRUE(res) << "decryption failed: it returned false\nmsg_len: "
                       << msg_len << "\nmsg : " << BytesToHex(msg)
                       << "\nct_len : " << ct_len << "\nct : " << BytesToHex(ct)
                       << "\n";

      std::vector<uint8_t> fakect(msg_len + a->overhead, 0x42);
      ASSERT_FALSE(a->open(&ctx, dec.data(), dec_secnonce.data(), fakect.data(),
                           fakect.size(), ad.data(), ad.size(),
                           pubnonce.data()))
          << "decryption failed: was able to successfully decrypt a fake ct: "
          << BytesToHex(ct);
    }
  }
}

INSTANTIATE_TEST_SUITE_P(
    AeadTest,
    AeadParamTests,
    ::testing::ValuesIn(cr::allAeads),
    [](const testing::TestParamInfo<AeadParamTests::ParamType> &info) {
      auto param = info.param;
      std::string name(param->name);
      std::replace(name.begin(), name.end(), '-', '_');
      std::replace(name.begin(), name.end(), '/', '_');
      return name;
    });

#ifdef CR_HAS_AREION

#include "../src/perm/areion/areion.h"

TEST(AeadTest, Areion256KAT) {
  // Areion256 test vectors from Appendix B of
  // https://eprint.iacr.org/2023/794.pdf
  std::map<std::string, std::string> in_out{
      {"0000000000000000000000000000000000000000000000000000000000000000",
       "2812a72465b26e9fca7583f6e4123aa1490e35e7d5203e4ba2e927b0482f4db8"},
      {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
       "68845f132ee4616066c702d942a3b2c3a377f65b13bb05c7cd1fb29c89afa185"}};

  for (const auto &[instr, outstr] : in_out) {
    auto invec = BytesFromHex(instr);
    auto got = std::vector<uint8_t>(invec.size(), 0x00);

    auto state = load256(invec.data());
    perm_areion256_forward(&state);
    store256(got.data(), state);
    ASSERT_EQ(outstr, BytesToHex(got))
        << "Areion256 permute forward doesn't match the KAT";

    perm_areion256_backward(&state);
    store256(got.data(), state);
    ASSERT_EQ(instr, BytesToHex(got))
        << "Areion256 permute backward doesn't match the KAT";
  }
}

TEST(AeadTest, Areion512KAT) {
  // Areion512 test vectors
  // NOTE: these do not match Appendix B of https://eprint.iacr.org/2023/794.pdf
  // clang-format off
  std::map<std::string, std::string> in_out{
      {"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
       "78cf3ee4b73c6a543fe6dc85779102e7e3f5501016ceed1dd2c48d0bc212fb07ad168794bd96cff35909cdd8e2274928b2adb04fa91f901559367122cb3c96a9",
       // Appendix B testvector
       // "b2adb04fa91f901559367122cb3c96a978cf3ee4b73c6a543fe6dc85779102e7e3f5501016ceed1dd2c48d0bc212fb07ad168794bd96cff35909cdd8e2274928",
      },
      {"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
       "135e9ac5fc3dc9b647a43f4daa8da7a4e0afbdd8e6e255c24527736b298bd61de460bab9ea7915c6d6ddbe05fe8dde40b690b88297ec470b07dda92b91959cff",
       // Appendix B testvector
       // "b690b88297ec470b07dda92b91959cff135e9ac5fc3dc9b647a43f4daa8da7a4e0afbdd8e6e255c24527736b298bd61de460bab9ea7915c6d6ddbe05fe8dde40",
      }};
  // clang-format on

  for (const auto &[instr, outstr] : in_out) {
    auto invec = BytesFromHex(instr);
    auto got = std::vector<uint8_t>(invec.size(), 0x00);

    u512_t state;
    state.u256[0] = load256(invec.data());
    state.u256[1] = load256(invec.data() + 32);
    perm_areion512_forward(&state);
    store256(got.data(), state.u256[0]);
    store256(got.data() + 32, state.u256[1]);
    ASSERT_EQ(outstr, BytesToHex(got))
        << "Areion512 permute forward doesn't match the KAT";

    // Areion512-Inverse is only implemented on Intel
#if CR_INTEL_HW
    perm_areion512_backward(&state);
    store256(got.data(), state.u256[0]);
    store256(got.data() + 32, state.u256[1]);
    ASSERT_EQ(instr, BytesToHex(got))
        << "Areion512 permute backward doesn't match the KAT";
#endif
  }
}

#endif

class AeadKat {
  // so google test can prettyprint
  friend void PrintTo(const AeadKat &kat, std::ostream *os) {
    *os << kat.testname;
  }

 public:
  std::string testname;
  const Aead *aead;
  std::string key;
  std::string pubnonce;
  std::string secnonce;
  std::string ad;
  std::string msg;
  std::string ct;
};

// clang-format off
std::vector<AeadKat> aead_kats{
#ifdef CR_HAS_AREION
    {"AreionOCH_S_0", Aead_och_s_areion(),
     "0000000000000000000000000000000000000000000000000000000000000000",
     "",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "94fb76019c4cc1bb2b8c745d749ccf0261e4c99041349b80a8e6c70e3cf9837e69f7a06a96353e5c3010ebd8db1d20c8cc5bd43eae6df364a10c2062b3f818e3c85ab5e5c9ca43e66bca16dbb5b5c240e86fa59167f895926775550583a250b8"},
    {"AreionOCH_P_0", Aead_och_p_areion(),
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "94fb76019c4cc1bb2b8c745d749ccf0261e4c99041349b80a8e6c70e3cf9837ebd367f85091b4989ae1d9276f918edc58412e61d451918ed96d89104dfc0d282"},
#endif  // CR_HAS_AREION
    {"SparkleOCH_S_0", Aead_och_s_sparkle(),
     "0000000000000000000000000000000000000000000000000000000000000000",
     "",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "c4a2d0d09bbab78b8c35ebc7fb2d63b0ad48a8d455e909cc6aa23b9ff0336ea6680fb01f9e0d6db8483f93c4c771f169beaeb731a5d241851ac117f7ae6b83b0769f092a83b2f073e08dfe8f980cca825098ab6fe582991640a8dde878c07070"},
    {"SparkleOCH_P_0", Aead_och_p_sparkle(),
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "0000000000000000000000000000000000000000000000000000000000000000",
     "c4a2d0d09bbab78b8c35ebc7fb2d63b0ad48a8d455e909cc6aa23b9ff0336ea6086c501dfc3dd2cfe573fb6099c056b1b8fdd3efbc91fb02c8d783f4d8f3e9bd"},
};
// clang-format on

class AeadKatTests : public ::testing::TestWithParam<AeadKat> {};

TEST_P(AeadKatTests, BasicAeadKats) {
  const auto [testname, a, keystr, pubnoncestr, secnoncestr, adstr, msgstr,
              ctstr] = GetParam();
  AeadKey ctx;
  memset(&ctx, 0, sizeof(ctx));

  const auto key = BytesFromHex(keystr);
  const auto pubnonce = BytesFromHex(pubnoncestr);
  const auto secnonce = BytesFromHex(secnoncestr);
  const auto ad = BytesFromHex(adstr);
  auto msg = BytesFromHex(msgstr);
  auto ct = BytesFromHex(ctstr);

  auto ct_len = msg.size() + a->overhead;
  std::vector<uint8_t> ct_got(ct_len, 0);
  std::vector<uint8_t> msg_got(msg.size(), 0);
  std::vector<uint8_t> secnonce_got(secnonce.size(), 0);

  ASSERT_TRUE(a->init(&ctx, key.data(), key.size()));
  ASSERT_TRUE(a->seal(&ctx, ct_got.data(), msg.data(), msg.size(), ad.data(),
                      ad.size(), pubnonce.data(), secnonce.data()));
  ASSERT_EQ(BytesToHex(ct_got), BytesToHex(ct))
      << "encryption failed to produce expected ciphertext";
  ASSERT_TRUE(a->open(&ctx, msg_got.data(), secnonce_got.data(), ct.data(),
                      ct.size(), ad.data(), ad.size(), pubnonce.data()));
  ASSERT_EQ(BytesToHex(msg_got), BytesToHex(msg))
      << "decryption failed to produce expected plaintext";
  ASSERT_EQ(BytesToHex(secnonce_got), BytesToHex(secnonce))
      << "decryption failed to produce expected secret nonce";
}

INSTANTIATE_TEST_SUITE_P(
    AeadTest,
    AeadKatTests,
    ::testing::ValuesIn(aead_kats),
    [](const testing::TestParamInfo<AeadKatTests::ParamType> &info) {
      auto param = info.param;
      return param.testname;
    });