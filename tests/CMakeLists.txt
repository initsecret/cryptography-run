# Use the new policy regarding timestamps of extracted files. Namely, use the
# timestamp of extraction not of the archive.
cmake_policy(
  SET
  CMP0135
  NEW)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.16.0.zip)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(aead_test aead_test.cc test-util.cc)
target_link_libraries(aead_test GTest::gtest_main)
target_link_libraries(aead_test cryptography-run)

add_executable(crhash_test crhash_test.cc test-util.cc)
target_link_libraries(crhash_test GTest::gtest_main)
target_link_libraries(crhash_test cryptography-run)

add_executable(axuhash_test axuhash_test.cc test-util.cc)
target_link_libraries(axuhash_test GTest::gtest_main)
target_link_libraries(axuhash_test cryptography-run)

add_executable(math_test math_test.cc test-util.cc)
target_link_libraries(math_test GTest::gtest_main)
target_link_libraries(math_test cryptography-run)

if(CR_x86_64)
  add_executable(cipher_test cipher_test.cc test-util.cc)
  target_link_libraries(cipher_test GTest::gtest_main)
  target_link_libraries(cipher_test cryptography-run)
endif()

include(GoogleTest)
# NOTE: need the longer discovery timeout on the slower RPi5
gtest_discover_tests(
  aead_test
  DISCOVERY_TIMEOUT
  600)
gtest_discover_tests(
  crhash_test
  DISCOVERY_TIMEOUT
  600)
gtest_discover_tests(
  axuhash_test
  DISCOVERY_TIMEOUT
  600)
gtest_discover_tests(
  math_test
  DISCOVERY_TIMEOUT
  600)

if(CR_x86_64)
  gtest_discover_tests(cipher_test)
endif()
