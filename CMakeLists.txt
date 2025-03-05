cmake_minimum_required(VERSION 3.0)
project(CPSM9)

set(CMAKE_CXX_STANDARD 17)
SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_BUILD_TYPE "Release")

find_package(OpenSSL REQUIRED)
include_directories(include)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -pthread -mavx2 -O3")
add_compile_options(-Wunknown-pragmas)

FIND_PACKAGE(OpenMP REQUIRED)
if (OPENMP_FOUND)
    message("OPENMP FOUND")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif ()

if (ENABLE_OMP)
    message("OpenMP enabled")
    add_definitions("-DParallel")
endif (ENABLE_OMP)

if (LOCAL_DEBUG)
    message("LOCAL_DEBUG enabled")
    add_definitions("-DDEBUG")
endif (LOCAL_DEBUG)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS}")

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
set(gtest_force_shared_crt ON)  # Windows需强制共享CRT
FetchContent_MakeAvailable(googletest)

# add_executable(unit_test_demo test.cpp)
# target_link_libraries(unit_test_demo gtest gmock gtest_main)

add_executable(CP_SM9_test src/scheme/CP_SM9.cc
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        unit_test/CP_SM9_test.cc)
        
target_link_libraries(CP_SM9_test gtest pbc OpenSSL::SSL
        "/lib/x86_64-linux-gnu/libgmpxx.a"
        "/lib/x86_64-linux-gnu/libgmp.a")

add_executable(IB_CH_Our_test src/scheme/IB_CH_Our.cpp
        src/curve/params.cpp
        src/base/ElementList.cpp
        src/utils/func.cpp
        unit_test/IB_CH_Our_test.cpp)
        
target_link_libraries(IB_CH_Our_test pbc OpenSSL::SSL
        "/lib/x86_64-linux-gnu/libgmpxx.a"
        "/lib/x86_64-linux-gnu/libgmp.a")
