#include <algorithm>
#include <cstdint>
#include "test-util.hpp"

#include <gtest/gtest.h>

#include <cryptography-run/aead.h>
#include <cryptography-run/axuhash.h>
#include <cryptography-run/hash.h>

class AxuHashParamTests : public ::testing::TestWithParam<const AxuHash *> {};

TEST_P(AxuHashParamTests, BasicAxuHash) {
  auto axu = GetParam();

  for (size_t msg_len : {16, 32, 48, 64, 80, 128}) {
    std::vector<uint8_t> key(axu->key_len, 0x42);
    std::vector<uint8_t> msg(msg_len, 0x42);
    std::vector<uint8_t> digest(axu->digest_len, 0xfa);
    std::vector<uint8_t> oneshot_digest(axu->digest_len, 0xaf);

    AxuHashKey axu_key;
    memset(&axu_key, 0, sizeof(axu_key));

    ASSERT_TRUE(axu->init(&axu_key, key.data(), key.size(), digest.size()));
    ASSERT_TRUE(axu->update_and_final(&axu_key, digest.data(), digest.size(),
                                      msg.data(), msg.size()));
  }
}

INSTANTIATE_TEST_SUITE_P(
    AxuHashTest,
    AxuHashParamTests,
    ::testing::Values(AxuHash_Poly1305(),
                      AxuHash_Polyval(),
                      AxuHash_X2Polyval()),
    [](const testing::TestParamInfo<AxuHashParamTests::ParamType> &info) {
      auto param = info.param;
      std::string name(param->name);
      std::replace(name.begin(), name.end(), '-', '_');
      return name;
    });

TEST(AxuHashTest, PolyvalKAT) {
  // Polyval KAT from https://www.rfc-editor.org/rfc/rfc8452.html#page-17
  const auto raw_key = BytesFromHex("25629347589242761d31f826ba4b757b");
  const auto in = BytesFromHex(
      "4f4f95668c83dfb6401762bb2d01a262"
      "d1a24ddd2721d006bbe45f20d3c9f362");
  const auto out = BytesFromHex("f7a3b47b846119fae5b7866cf5e5b77e");

  auto buf = std::vector<uint8_t>(out.size());

  auto axu = AxuHash_Polyval();
  AxuHashKey axu_key;
  memset(&axu_key, 0, sizeof(axu_key));

  ASSERT_TRUE(axu->init(&axu_key, raw_key.data(), raw_key.size(), out.size()));
  ASSERT_TRUE(axu->update_and_final(&axu_key, buf.data(), buf.size(), in.data(),
                                    in.size()));
  ASSERT_EQ(BytesToHex(out), BytesToHex(buf)) << "Polyval KAT failed";
}
