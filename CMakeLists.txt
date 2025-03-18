cmake_minimum_required(VERSION 3.0)
project(CPSM9 VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
SET(CMAKE_BUILD_TYPE "Debug")
SET(CMAKE_BUILD_TYPE "Release")

find_package(OpenSSL REQUIRED)
include_directories(include)

find_package(Eigen3 3.4 REQUIRED)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17 -pthread -mavx2 -O3")
add_compile_options(-Wunknown-pragmas)

set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} -g -ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS}")

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
set(gtest_force_shared_crt ON)
FetchContent_MakeAvailable(googletest)

add_executable(w11_test
        test/w11_test.cc
        src/crypto/w11.cc
        src/utils/lsss.cc
        src/utils/hash.cc
        src/curve/params.cc)
        
target_link_libraries(w11_test gtest pbc OpenSSL::SSL
        "/lib/x86_64-linux-gnu/libgmpxx.a"
        "/lib/x86_64-linux-gnu/libgmp.a")

add_executable(susm9_test
        test/susm9_test.cc
        src/crypto/susm9.cc
        src/utils/lsss.cc
        src/utils/hash.cc
        src/curve/params.cc)
        
target_link_libraries(susm9_test gtest pbc OpenSSL::SSL
        "/lib/x86_64-linux-gnu/libgmpxx.a"
        "/lib/x86_64-linux-gnu/libgmp.a")

add_executable(lsss_test
        test/lsss_test.cc
        src/utils/lsss.cc
        src/curve/params.cc)

target_link_libraries(lsss_test gtest pbc Eigen3::Eigen)
