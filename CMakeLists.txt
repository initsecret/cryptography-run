cmake_minimum_required(VERSION 3.15)

project(cryptography-run VERSION 0.1)

# Core library uses only C, but benches and tests use C++. All platforms we
# support including 32-bit ARM have C++ compilers.
enable_language(ASM)
enable_language(C)
set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
enable_language(CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

message(STATUS "Using toolchain file: ${CMAKE_TOOLCHAIN_FILE}")

# enable all warnings
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
# we include headers with extra static functions
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-unused-function")
# we include code that defines params as arrays but implements as pointers
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-array-parameter")

# use color diagnostics and save intermediate results
set(CR_FLAGS "-fdiagnostics-color=always")

# NOTE: CMAKE_BUILD_TYPE is set with command-line arguments
if(CMAKE_BUILD_TYPE
   STREQUAL
   "Release")
  message(STATUS "Release build with all optimizations")
  set(CR_FLAGS "${CR_FLAGS} -fomit-frame-pointer -O3")
elseif(
  CMAKE_BUILD_TYPE
  STREQUAL
  "Debug")
  message(
    WARNING "Debug build uses sanitizers and does not enable all optimizations")
  set(CR_FLAGS "${CR_FLAGS} -fsanitize=address,undefined")
else()
  message(FATAL_ERROR "Unknown build type")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${CR_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CR_FLAGS}")

# Generate compile_commands.json for use by clang-tidy and other tools.
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# MacOS specific things
if(CMAKE_SYSTEM_NAME
   STREQUAL
   "Darwin")
  set(CMAKE_OSX_DEPLOYMENT_TARGET 15.5)
endif()

if(CMAKE_SYSTEM_PROCESSOR
   STREQUAL
   "x86_64")
  set(CR_x86_64 1)
elseif(
  (CMAKE_SYSTEM_PROCESSOR
   STREQUAL
   "arm64")
  OR (CMAKE_SYSTEM_PROCESSOR
      STREQUAL
      "aarch64"))
  set(CR_aarch64 1)
else()
  message(
    FATAL_ERROR
      "unsupported architecture ${CMAKE_SYSTEM_PROCESSOR}, only x86_64 and aarch64/arm64 are supported"
  )
endif()

# NOTE: THIRD_PARTY_FOLDER is set with command-line arguments

# Import libsodium
add_library(
  libsodium
  STATIC
  IMPORTED)
set_property(
  TARGET libsodium
  PROPERTY IMPORTED_LOCATION
           "${THIRD_PARTY_FOLDER}/libsodium-build/lib/libsodium.a")
target_include_directories(
  libsodium INTERFACE "${THIRD_PARTY_FOLDER}/libsodium-build/include")

# Import libXKCP
add_library(
  libXKCP
  STATIC
  IMPORTED)
if(CR_x86_64)
  set_property(
    TARGET libXKCP PROPERTY IMPORTED_LOCATION
                            "${THIRD_PARTY_FOLDER}/XKCP/bin/AVX2/libXKCP.a")
  target_include_directories(
    libXKCP INTERFACE "${THIRD_PARTY_FOLDER}/XKCP/bin/AVX2/libXKCP.a.headers")
elseif(CR_aarch64)
  set_property(
    TARGET libXKCP PROPERTY IMPORTED_LOCATION
                            "${THIRD_PARTY_FOLDER}/XKCP/bin/ARMv8A/libXKCP.a")
  target_include_directories(
    libXKCP INTERFACE "${THIRD_PARTY_FOLDER}/XKCP/bin/ARMv8A/libXKCP.a.headers")
endif()

# Import ascon
add_library(
  ascon
  STATIC
  IMPORTED)
set_property(
  TARGET ascon
  PROPERTY
    IMPORTED_LOCATION
    "${THIRD_PARTY_FOLDER}/ascon-c/build/libcrypto_aead_asconaeadxof128_opt64.a"
)
target_include_directories(
  ascon INTERFACE "${THIRD_PARTY_FOLDER}/asconaeadxof128.headers")

# Import boringssl
add_library(
  boringssl
  STATIC
  IMPORTED)
set_property(
  TARGET boringssl
  PROPERTY IMPORTED_LOCATION
           "${THIRD_PARTY_FOLDER}/boringssl-build/lib/libcrypto.a")
target_include_directories(
  boringssl INTERFACE "${THIRD_PARTY_FOLDER}/boringssl-build/include")

# Import libaegis
add_library(
  libaegis
  STATIC
  IMPORTED)
set_property(
  TARGET libaegis
  PROPERTY IMPORTED_LOCATION
           "${THIRD_PARTY_FOLDER}/libaegis/zig-out/lib/libaegis.a")
target_include_directories(
  libaegis INTERFACE "${THIRD_PARTY_FOLDER}/libaegis/zig-out/include")

# Build sources, tests, and benches
add_subdirectory(src)
add_subdirectory(tests)
add_subdirectory(benches)
