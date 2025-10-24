#include "test-util.hpp"

#include <iomanip>
#include <ios>
#include <sstream>
#include <string>

std::vector<uint8_t> BytesFromHex(const std::string hexstring) {
  std::vector<uint8_t> out;
  for (auto it = hexstring.begin(); it < hexstring.end(); it += 2) {
    std::string hexChar(it, it + 2);
    auto b = std::stoul(hexChar, 0, 16);
    out.push_back(b);
  }
  return out;
}

std::vector<uint8_t> BytesFromChar(const std::string charstring) {
  std::vector<uint8_t> out;
  for (auto c : charstring) {
    out.push_back(c);
  }
  return out;
}

std::string BytesToHex(const uint8_t in[], size_t in_len) {
  std::stringstream out;
  for (auto i = 0; i < in_len; ++i) {
    out << std::hex << std::setfill('0') << std::setw(2)
        << static_cast<int>(in[i]);
  }
  return out.str();
}

std::string BytesToHex(const std::vector<uint8_t> in) {
  return BytesToHex(in.data(), in.size());
}

std::string NumToHex(const u128_t in) {
  return BytesToHex(in.u8, CR_U128_BYTES);
}

std::string NumToHex(const u256_t in) {
  return BytesToHex(in.u8, CR_U256_BYTES);
}

std::string NumToHex(const u512_t in) {
  return BytesToHex(in.u8, CR_U512_BYTES);
}

#ifdef __x86_64__

std::string U256ToHex(__m256i in) {
  uint8_t out[32] = {0};
  _mm256_storeu_si256((__m256i *)out, in);
  return BytesToHex(out, 32);
}

#endif  // __x86_64__
