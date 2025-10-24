#ifndef CR_BENCH_UTILS_HPP
#define CR_BENCH_UTILS_HPP

#include <chrono>
#include <ctime>

static std::string unix_timestamp() {
  const auto time_now = std::chrono::system_clock::now();
  return std::to_string(std::chrono::duration_cast<std::chrono::seconds>(
                            time_now.time_since_epoch())
                            .count());
}

#include <unistd.h>

static std::string unix_hostname() {
  char chostname[100] = {};
  gethostname(chostname, 100);
  std::string out = chostname;
  return out;
}

#endif  // CR_BENCH_UTILS_HPP
