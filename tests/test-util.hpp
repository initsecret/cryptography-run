#ifndef CR_TEST_UTIL_HPP
#define CR_TEST_UTIL_HPP

#include <cstdint>
#include <string>
#include <vector>

#include <cryptography-run/base.h>

std::vector<uint8_t> BytesFromHex(const std::string hexstring);
std::vector<uint8_t> BytesFromChar(const std::string charstring);

std::string BytesToHex(const uint8_t in[], size_t in_len);
std::string BytesToHex(const std::vector<uint8_t> in);

std::string NumToHex(const u128_t in);
std::string NumToHex(const u256_t in);
std::string NumToHex(const u512_t in);

#ifdef __x86_64__
#include <immintrin.h>
std::string U256ToHex(const __m256i in);
#endif  // __x86_64__

#endif  // CR_TEST_UTIL_HPP