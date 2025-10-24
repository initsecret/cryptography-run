include(CheckIPOSupported)
check_ipo_supported(RESULT ipo_supported OUTPUT error)

add_executable(speed speed.cc)
target_link_libraries(speed PRIVATE cryptography-run)

if(ipo_supported)
  message(STATUS "IPO / LTO enabled")
  set_property(TARGET speed PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
else()
  message(STATUS "IPO / LTO not supported: <${error}>")
endif()
