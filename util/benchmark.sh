#!/bin/bash

# exit if any command fails
set -e

# Build and run tests
rm -rf build_release
./util/format.sh
cmake -S . -B build_release -DCMAKE_BUILD_TYPE=Release
cmake --build build_release
ctest --output-on-failure --test-dir build_release/tests

# 1. on Intel, disable turbo boost and verify
echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
cat /sys/devices/system/cpu/intel_pstate/no_turbo
# 2. set cpus to maximum frequency and verify
sudo cpupower frequency-set --governor performance
cpupower frequency-info --proc
# 3. run benchmark on a fixed core
#    inside perf-stat to enable performance counters: https://stackoverflow.com/a/56193850
taskset --cpu-list 4 perf stat -e instructions:u ./build_release/benches/benches


# 1. re-enable turbo boost
echo 0 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo
cat /sys/devices/system/cpu/intel_pstate/no_turbo
# 2. reset cpus to back to powersave and verify
sudo cpupower frequency-set --governor powersave
cpupower frequency-info --proc
# 3. process results
./util/process.py
