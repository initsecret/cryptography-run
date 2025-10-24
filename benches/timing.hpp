#ifndef CR_TIMING_HPP
#define CR_TIMING_HPP

#include <cinttypes>
#include <ctime>
#include <functional>
#include <string>

#include "benches.hpp"

/** TimeResults represents the results of benchmarking a function. */
struct TimeResults {
  // num_calls is the number of function calls done in the time period.
  uint64_t num_calls;
  // us is the number of microseconds that elapsed in the time period.
  uint64_t us;
  // cycles is the number of cycles that elapsed in the time period.
  uint64_t cycles;

  // print_json determines whether to print JSON
  static bool print_json;

  /**
   * returns whether the cycles per byte number is in the expected range.
   */
  bool IsReasonable(size_t msg_len, size_t ad_len) {
#if CR_MEASURE_CYCLES
    double cycles_per_byte = 0;
    if (msg_len > 0) {
      cycles_per_byte = static_cast<double>(cycles) /
                        static_cast<double>(msg_len * num_calls);
    }
    if (cycles_per_byte > 1000000) {
      if (CR_PRINT_DEBUG) {
        fprintf(stderr, "got unreasonable cycles per byte: %.1f\n",
                cycles_per_byte);
      }
      return false;
    }
#endif
    return true;
  }
  void PrintAead(const std::string &name,
                 const AeadOperation op,
                 size_t msg_len,
                 size_t ad_len) const {
    auto ops_per_second =
        (static_cast<double>(num_calls) / static_cast<double>(us)) * 1000000;
    auto mb_per_second =
        static_cast<double>(msg_len * num_calls) / static_cast<double>(us);
    double cycles_per_byte = 0;
#if CR_MEASURE_CYCLES
    if (msg_len > 0) {
      cycles_per_byte = static_cast<double>(cycles) /
                        static_cast<double>(msg_len * num_calls);
    }
#endif

    if (print_json) {
      PrintAeadJSON(name, op, msg_len, ad_len, ops_per_second, mb_per_second,
                    cycles_per_byte);
    } else {
      PrintAeadTerm(name, op, msg_len, ad_len, ops_per_second, mb_per_second,
                    cycles_per_byte);
    }
  }

 private:
  void PrintAeadTerm(const std::string &name,
                     const AeadOperation op,
                     size_t msg_len,
                     size_t ad_len,
                     double ops_per_second,
                     double mb_per_second,
                     double cycles_per_byte) const {
#if CR_MEASURE_CYCLES
    printf("%22s | %-22s | m: %lu | ad: %lu | %6.1f MB/s | %6.3f c/B\n",
           to_string(op).c_str(), name.c_str(), msg_len, ad_len, mb_per_second,
           cycles_per_byte);
#else
    printf("%10s | %-22s | m: %lu | ad: %lu | %6.1f MB/s\n",
           to_string(op).c_str(), name.c_str(), msg_len, ad_len, mb_per_second);
#endif
  }

  void PrintAeadJSON(const std::string &name,
                     const AeadOperation op,
                     size_t msg_len,
                     size_t ad_len,
                     double ops_per_second,
                     double mb_per_second,
                     double cycles_per_byte) const {
    if (first_json_printed) {
      puts(",");
    }
    printf(
        "    {\"name\": \"%s\""
        ", \"operation\": \"%s\""
        ", \"msg_len\": %lu"
        ", \"ad_len\": %lu"
        ", \"numCalls\": %" PRIu64 ", \"microseconds\": %" PRIu64
        ", \"ops_per_second\": %.3f"
        ", \"mb_per_second\": %.3f",
        name.c_str(), to_string(op).c_str(), msg_len, ad_len, num_calls, us,
        ops_per_second, mb_per_second);
#if CR_MEASURE_CYCLES
    printf(", \"cycles\": %" PRIu64 ", \"cycles_per_byte\": %.3f", cycles,
           cycles_per_byte);
#endif
    printf("}");
    first_json_printed = true;
  }

  // first_json_printed is true if |g_print_json| is true and the first item
  // in the JSON results has been printed already. This is used to handle the
  // commas between each item in the result list.
  static bool first_json_printed;
};

static uint64_t time_now() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);

  uint64_t ret = ts.tv_sec;
  ret *= 1000000;
  ret += ts.tv_nsec / 1000;
  return ret;
}

/**
 * Current cycle count:
 *
 * Adapted from
 * https://github.com/pornin/cycle-counter/tree/main?tab=readme-ov-file#x86
 * https://github.com/pornin/cycle-counter/tree/main?tab=readme-ov-file#armv8
 */
static inline int64_t cycles_now() {
#if defined(__x86_64__) && defined(__linux__)
#include <x86intrin.h>
  _mm_lfence();
  return __rdpmc(0x40000001);
#elif defined(__aarch64__) && defined(__linux__)
  uint64_t x;
  __asm__ __volatile__("dsb sy\n\tmrs %0, pmccntr_el0" : "=r"(x) : :);
  return x;
#else
  // unimplemented on other platforms
  assert(false);
  return 0;
#endif
}

// IterationsBetweenTimeChecks returns the number of iterations of |func| to
// run in between checking the time, or zero on error.
static uint32_t IterationsBetweenTimeChecks(std::function<bool()> func) {
  uint64_t start = time_now();
  if (!func()) {
    return 0;
  }
  uint64_t delta = time_now() - start;
  if (delta == 0) {
    return 250;
  }

  // Aim for about 10ms between time checks.
  uint32_t ret = static_cast<double>(between_us) / static_cast<double>(delta);
  if (ret > 1000) {
    ret = 1000;
  } else if (ret < 1) {
    ret = 1;
  }
  return ret;
}

static bool TimeFunctionImpl(TimeResults *results,
                             std::function<bool()> func,
                             uint32_t iterations_between_time_checks) {
  uint64_t now_us = 0;
  uint64_t done = 0;
  uint64_t start_us = time_now();
#if CR_MEASURE_CYCLES
  uint64_t now_cycles = 0;
  uint64_t start_cycles = cycles_now();
#endif
  for (;;) {
    for (uint32_t i = 0; i < iterations_between_time_checks; i++) {
      if (!func()) {
        return false;
      }
      done++;
    }

#if CR_MEASURE_CYCLES
    now_cycles = cycles_now();
#endif
    now_us = time_now();
    if (now_us - start_us > total_us) {
      break;
    }
  }

  results->us = now_us - start_us;
#if CR_MEASURE_CYCLES
  results->cycles = now_cycles - start_cycles;
#endif
  results->num_calls = done;
  return true;
}

static bool TimeFunction(TimeResults *results, std::function<bool()> func) {
  uint32_t iterations_between_time_checks = IterationsBetweenTimeChecks(func);
  if (iterations_between_time_checks == 0) {
    return false;
  }

  return TimeFunctionImpl(results, std::move(func),
                          iterations_between_time_checks);
}

#define AttemptWithRetry(speed_fn)                \
  {                                               \
    bool retried = false;                         \
    for (int i = 0; i < MAX_RETRY; i++) {         \
      if ((speed_fn)) {                           \
        if (retried && CR_PRINT_DEBUG) {          \
          fprintf(stderr, "succeded on retry\n"); \
        }                                         \
        return true;                              \
      }                                           \
      retried = true;                             \
    }                                             \
    return false;                                 \
  }

#endif  // CR_TIMING_HPP
