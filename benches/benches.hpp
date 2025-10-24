// Based on
// https://github.com/google/boringssl/blob/a9993612faac4866bc33ca8ff37bfd0659af1c48/tool/speed.cc

// Copyright 2014 The BoringSSL Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef CR_BENCHES_HPP
#define CR_BENCHES_HPP

#include <cstdint>
#include <cstdio>
#include <string>

/** maximum number of retries when the data is invalid */
const auto MAX_RETRY = 8;

/** total amount of time that we'll aim to measure a function for */
static const uint64_t total_us = 100 * 1000;  // 100ms

/** time between time checks */
static const uint64_t between_us = 10 * 1000;  // 10ms

/** aead operations to benchmark */
enum class AeadOperation {
  hot_seal_rand_nonce,
  cold_seal_rand_nonce,
  hot_seal_seq_nonce,
  hot_open,
};

/* whether to measure cycles */
#if defined(__x86_64__) && defined(__linux__)
#define CR_MEASURE_CYCLES true
#include <x86intrin.h> /* to count cycles */
#elif defined(__aarch64__) && defined(__linux__)
#define CR_MEASURE_CYCLES true
#else
/* unsupported */
#define CR_MEASURE_CYCLES false
#endif

static std::string to_string(AeadOperation op) {
  std::string result;
  switch (op) {
    case AeadOperation::hot_seal_rand_nonce:
      result = "hot_seal_rand_nonce";
      break;
    case AeadOperation::cold_seal_rand_nonce:
      result = "cold_seal_rand_nonce";
      break;
    case AeadOperation::hot_seal_seq_nonce:
      result = "hot_seal_seq_nonce";
      break;
    case AeadOperation::hot_open:
      result = "hot_open";
      break;
  }
  return result;
}

/* prints debug messages to stderr */
#define CR_PRINT_DEBUG false

#endif  // CR_BENCHES_HPP
