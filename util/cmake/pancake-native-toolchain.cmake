set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native" CACHE STRING "c++ flags")
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -march=native" CACHE STRING "c flags")
set(CMAKE_ASM_FLAGS "${CMAKE_ASM_FLAGS} -march=native" CACHE STRING "asm flags")
