#!/usr/bin/python3

"""
Runs the program to generate benchmarks
"""

import os
import subprocess
import argparse
import sys
import datetime
import time
import platform

from results import process_results


VERSION = "v0.2"
PRECISION = 3  # decimal points in mean and stddev

# turns "offside.local" into "offside"
hostname = platform.node().split(".")[0]

if hostname == "pancake":
    # Raspberry Pi5
    assert platform.machine() == "aarch64"
    assert platform.system() == "Linux"
    cr_folder = os.environ["HOME"] + "/cryptography-run/"
elif hostname == "hitch":
    # Intel NUC
    assert platform.machine() == "x86_64"
    assert platform.system() == "Linux"
    cr_folder = os.environ["HOME"] + "/cryptography-run/"
elif hostname == "offside":
    # Macbook Pro
    assert platform.machine() == "arm64"
    assert platform.system() == "Darwin"
    cr_folder = os.environ["HOME"] + "/Documents/Research/cryptography-run/"
else:
    print(f"WARNING: unknown host {hostname}")
    cr_folder = os.environ["HOME"] + "/Documents/Research/cryptography-run/"

RESULT_JSON = f"{cr_folder}/data/results/results-{hostname}-{int(time.time())}.json"


CMAKE_COMMON = f"-GNinja -DTHIRD_PARTY_FOLDER={cr_folder}/3rdparty/ -DCMAKE_TOOLCHAIN_FILE={cr_folder}/util/cmake/{hostname}-native-toolchain.cmake"

CMAKE_DEBUG_CLI_FLAGS = f"{CMAKE_COMMON} -DCMAKE_BUILD_TYPE=Debug"
CMAKE_RELEASE_CLI_FLAGS = f"{CMAKE_COMMON} -DCMAKE_BUILD_TYPE=Release"

DEBUG_FOLDER = "build_debug"
RELEASE_FOLDER = "build_release"

if platform.system() == "Linux":
    with open(f"{cr_folder}/util/expect/{platform.node()}_proc_perf.txt") as f:
        PROC_PERF_EXPECT = f.read()
    with open(f"{cr_folder}/util/expect/{platform.node()}_lscpu.txt") as f:
        LSCPU_EXPECT = f.read()


def run(command, expect=None, exit_on_fail=True):
    """
    returns true if command succeeds && expect (if not None) succeeds
    else returns false or exits
    """
    ret = subprocess.run(command, shell=True, capture_output=True)
    so = ret.stdout.decode("utf8")
    se = ret.stderr.decode("utf8")
    if expect == None:
        if so:
            print(so, end=None)
        if se:
            print(se, file=sys.stderr, end=None)

    if ret.returncode != 0:
        print(f"COMMAND FAILED: {command}", file=sys.stderr)
        if exit_on_fail:
            sys.exit(-1)
        return False

    if expect != None:
        if so.strip() != expect.strip():
            if exit_on_fail:
                print(f'EXPECT FAILED: {command} => got: "{so}", expected: "{expect}"')
                sys.exit(-1)
            return False

        print(f"EXPECT SUCCEEDED: {command} => {expect}")

    return True


def enable_cycle_counters():
    # on Intel, check that rdpmc is readable
    # from https://github.com/pornin/cycle-counter/
    if platform.machine() == "x86_64":
        if not run(
            "sudo cat /sys/bus/event_source/devices/cpu_core/rdpmc",
            expect="2",
            exit_on_fail=False,
        ):
            run("echo 2 | sudo tee /sys/bus/event_source/devices/cpu_core/rdpmc")
            run("sudo cat /sys/bus/event_source/devices/cpu_core/rdpmc", expect="2")
    # on aarch64, check that the cyccnt module is loaded
    if platform.machine() == "aarch64":
        assert platform.node() == "pancake"
        if not run("lsmod | grep --count cyccnt", expect="1", exit_on_fail=False):
            run(
                f"cd {cr_folder}/3rdparty/cycle-counter/cyccnt && make clean && make && sudo insmod cyccnt.ko"
            )
            run("lsmod | grep --count cyccnt", expect="1")


def prepare_for_bench():
    # on Intel, disable turbo boost
    if platform.machine() == "x86_64":
        if not run(
            "cat /sys/devices/system/cpu/intel_pstate/no_turbo",
            expect="1",
            exit_on_fail=False,
        ):
            run("echo 1 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo")
            run("cat /sys/devices/system/cpu/intel_pstate/no_turbo", expect="1")
    # if CPUs are not set to maximum frequency, then set and verify
    if not run(
        "cpupower frequency-info --proc",
        expect=PROC_PERF_EXPECT,
        exit_on_fail=False,
    ):
        print("SETTING CPU FREQUENCY")
        run("sudo cpupower frequency-set --governor performance")
        time.sleep(2)
        run("cpupower frequency-info --proc", expect=PROC_PERF_EXPECT)


def reset_after_bench():
    # reset cpus to back to powersave and verify
    run("sudo cpupower frequency-set --governor powersave")
    run("cpupower frequency-info --proc")
    # on Intel, re-enable turbo boost and verify
    if platform.machine() == "x86_64":
        run("echo 0 | sudo tee /sys/devices/system/cpu/intel_pstate/no_turbo")
        run("cat /sys/devices/system/cpu/intel_pstate/no_turbo", expect="0")


def format_files():
    for folder in ["benches", "include", "src", "tests", "util"]:
        run(f"find {folder} -name '*.[ch]' -exec clang-format -i {{}} ';'")
        run(f"find {folder} -name '*.cc' -exec clang-format -i {{}} ';'")
        run(f"find {folder} -name '*.hpp' -exec clang-format -i {{}} ';'")
    if platform.machine() == "x86_64":
        run("black --quiet ./util/*.py")
        # cmake-format from https://github.com/cheshirekow/cmake_format
        run(f"find . -name 'CMakeLists.txt' -exec cmake-format -i {{}} ';'")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        prog="cryptography-run",
        description="What the program does",
        epilog="Text at the bottom of help",
    )

    parser.add_argument("-c", "--clean", help="clean build files", action="store_true")
    parser.add_argument("--release", help="do release build", action="store_true")
    parser.add_argument(
        "--quick-bench",
        help="run quick benchmark and print to terminal",
        action="store_true",
    )
    parser.add_argument(
        "--bench", help="run full benchmark and generate json", action="store_true"
    )
    parser.add_argument("--tests", help="run tests", action="store_true")
    parser.add_argument("--testselect", help="select tests with regex")
    parser.add_argument("--process-file", help="results.json file to process")

    args = parser.parse_args()

    print(args)

    if args.process_file:
        process_results(args.process_file)
        sys.exit(0)

    if args.clean:
        run(f"rm -rf {DEBUG_FOLDER}")
        run(f"rm -rf {RELEASE_FOLDER}")

    format_files()

    # always build debug
    run(f"cmake -S . -B {DEBUG_FOLDER} {CMAKE_DEBUG_CLI_FLAGS}")
    run(f"cmake --build {DEBUG_FOLDER}")
    run(f"cp {DEBUG_FOLDER}/compile_commands.json .")

    # run tests by default, except on pancake
    if (platform.node() != "pancake") or args.tests or args.testselect:
        testselect = ""
        if args.testselect:
            testselect = f"-R {args.testselect}"
        run(f"ctest --output-on-failure --test-dir {DEBUG_FOLDER}/tests {testselect}")

    # build release by default, except on pancake
    if (platform.node() != "pancake") or args.bench or args.release or args.quick_bench:
        run(f"cmake -S . -B {RELEASE_FOLDER} {CMAKE_RELEASE_CLI_FLAGS}")
        run(f"cmake --build {RELEASE_FOLDER}")

    if args.bench or args.quick_bench:
        if args.quick_bench:
            print(
                "WARNING: Quick benchmarks are less accurate because we don't try as hard to reduce variance."
            )
        if platform.system() != "Linux":
            print(
                "WARNING: Benchmarks on not-Linux are less accurate because we have less control over the CPU."
            )

        benchprefix = ""
        if not args.quick_bench:
            # run all tests on the release build before benchmarking
            run(f"ctest --output-on-failure --test-dir {RELEASE_FOLDER}/tests")

            # run benchmark on a fixed core
            if platform.system() == "Linux":
                benchprefix = "taskset --cpu-list 2 "
                prepare_for_bench()

        # enable cycle counters on Linux
        if platform.system() == "Linux":
            enable_cycle_counters()

        print(f"STARTED BENCH at\t{datetime.datetime.now().ctime()}")

        benchargs = ""
        if args.quick_bench:
            benchargs = "-quick"
        else:
            benchargs = f"-json > {RESULT_JSON}"

        run(f"{benchprefix} ./build_release/benches/speed {benchargs}")

        print(f"FINISHED BENCH at\t{datetime.datetime.now().ctime()}")

        if not args.quick_bench:
            print(f"WROTE RESULTS TO {RESULT_JSON}")

        if not args.quick_bench and platform.system() == "Linux":
            reset_after_bench()

        if not args.quick_bench:
            process_results(RESULT_JSON)
