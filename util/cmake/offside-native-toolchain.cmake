set(CMAKE_SYSTEM_NAME Darwin)
set(CMAKE_SYSTEM_PROCESSOR arm64)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -arch arm64 -march=armv8+crypto" CACHE STRING "c++ flags")
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -arch arm64 -march=armv8+crypto" CACHE STRING "c flags")
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -arch arm64 -march=armv8+crypto" CACHE STRING "asm flags")
