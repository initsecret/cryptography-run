#include "test-util.hpp"

#include <gtest/gtest.h>

#include <cryptography-run/base.h>
#include <cryptography-run/gf128.h>
#include <cryptography-run/gf256.h>

TEST(MathTest, Gf128BasicOps) {
  // From https://www.rfc-editor.org/rfc/rfc8452.html#section-7

  const auto a =
      load128(BytesFromHex("66e94bd4ef8a2c3b884cfa59ca342b2e").data());
  const auto b =
      load128(BytesFromHex("ff000000000000000000000000000000").data());

  // TODO: enable this test after implementing gf128.h
  // expected values
  // const auto a_plus_b = "99e94bd4ef8a2c3b884cfa59ca342b2e";
  // const auto a_mul_b = "37856175e9dc9df26ebc6d6171aa0ae9";
  const auto a_dot_b = "ebe563401e7e91ea3ad6426b8140c394";

  u128_t out = a;
  gf128_dot(&out, &b);
  ASSERT_EQ(a_dot_b, NumToHex(out));

  // ASSERT_EQ(a_plus_b, NumToHex(gf128_add(a, b)));
  // ASSERT_EQ(a_mul_b, NumToHex(gf128_mul(a, b)));
  // ASSERT_EQ(a_dot_b, NumToHex(gf128_dot(a, b)));
}

TEST(MathTest, Gf256Double) {
  std::map<std::string, std::string> out_in{
      // x^255 = 0x80... = 0b100...
      // double(x^255) = x * x^255 = x^10 + x^5 + x^2 + 1
      //                           = 0b10000100101
      //                           = 0x0425
      {"0000000000000000000000000000000000000000000000000000000000000425",
       "8000000000000000000000000000000000000000000000000000000000000000"},
      {"fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbdb",
       "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"},
      {"2000000000000000000000000000000000000000000000000000000000000000",
       "1000000000000000000000000000000000000000000000000000000000000000"},
      {"0000000000000000000000000000000000000000000000000000000000000000",
       "0000000000000000000000000000000000000000000000000000000000000000"},
      {"0000000000000000000000000000000000000000000000000000000000000002",
       "0000000000000000000000000000000000000000000000000000000000000001"},
      {"0000000000000000000000000000000000000000000000000000000000000010",
       "0000000000000000000000000000000000000000000000000000000000000008"},
  };
  for (const auto &[outstr, instr] : out_in) {
    auto in = BytesFromHex(instr);
    auto in_num = load256(in.data());
    auto gotstr = BytesToHex(gf256_double(in_num).u8, 32);
    ASSERT_EQ(outstr, gotstr);
  }
}