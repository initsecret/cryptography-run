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

#include <sys/random.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <set>
#include <string>

#include "aead_benches.hpp"
#include "bench_utils.hpp"
#include "timing.hpp"

#include "../3rdparty/toml.hpp"

bool TimeResults::first_json_printed = false;
bool TimeResults::print_json = false;

static bool SpeedAllAeadBenches() {
  for (const auto &bench : aead_benches) {
    if (!SpeedAeadBench(bench)) {
      fprintf(stderr, "Failed AEAD bench: %s\n", bench.benchname.c_str());
      return false;
    }
  }
  return true;
}

static bool SpeedQuickAeadBenches() {
  for (const auto &bench : quick_aead_benches) {
    if (!SpeedAeadBench(bench)) {
      fprintf(stderr, "Failed AEAD bench: %s\n", bench.benchname.c_str());
      return false;
    }
  }
  return true;
}

bool Speed(const std::set<std::string> &args) {
  // output json unless a quick bench is requested
  bool quick_bench = args.contains("-quick");
  TimeResults::print_json = !quick_bench;

  if (TimeResults::print_json) {
    auto ts = unix_timestamp();
    auto hn = unix_hostname();

    puts("{");
    printf("  \"hostname\": \"%s\",\n", hn.c_str());
    printf("  \"timestamp\": %s,\n", ts.c_str());
    printf("  \"measurements\": [\n");
  }

  if (!quick_bench) {
    for (int i = 0; i < AEAD_REPEAT; ++i) {
      if (!SpeedAllAeadBenches()) {
        fprintf(stderr, "Failed to run AEAD benchmarks\n");
        return false;
      }
    }
  } else {
    if (!SpeedQuickAeadBenches()) {
      fprintf(stderr, "Failed to run quick AEAD benchmarks\n");
      return false;
    }
  }

  if (TimeResults::print_json) {
    puts("  ]");
    puts("}");
  }
  return true;
}

int main(int argc, char **argv) {
  std::set<std::string> args;
  for (int i = 0; i < argc; i++) {
    args.insert(argv[i]);
  }
  if (!Speed(args)) {
    return 1;
  }
  return 0;
}
