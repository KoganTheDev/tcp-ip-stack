# Microbenchmarks, configured by the `bench` preset. Google Benchmark is
# fetched at a pinned release (it is not a distribution dependency of this
# project, and the benchmark history in bench.yml compares numbers across
# commits, so the library measuring them must not drift under it).
include(FetchContent)

# Benchmark's own tests and install rules are not wanted, and the gtest-based
# ones would need GoogleTest, which the bench preset does not otherwise build.
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
set(BENCHMARK_INSTALL_DOCS OFF CACHE BOOL "" FORCE)

set(BENCH_FETCH_ARGS
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG v1.10.0
    GIT_SHALLOW TRUE)
# SYSTEM keeps warnings from the library's headers out of our build.
if(CMAKE_VERSION VERSION_GREATER_EQUAL 3.25)
    list(APPEND BENCH_FETCH_ARGS SYSTEM)
endif()
FetchContent_Declare(benchmark ${BENCH_FETCH_ARGS})
FetchContent_MakeAvailable(benchmark)

file(GLOB BENCH_SOURCES CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/bench/*.cpp)

# The end-to-end benchmark drives the same network simulator the tests use, so
# its sources are compiled in from tests/src/ rather than copied. They are
# plain C++ (no GoogleTest).
add_executable(tcpip_bench ${BENCH_SOURCES}
    ${PROJECT_SOURCE_DIR}/tests/src/sim_network.cpp
    ${PROJECT_SOURCE_DIR}/tests/src/sim_netem_channel.cpp
    ${PROJECT_SOURCE_DIR}/tests/src/sim_tcp_frame.cpp)
target_include_directories(tcpip_bench PRIVATE ${PROJECT_SOURCE_DIR}/tests/include)
target_link_libraries(tcpip_bench PRIVATE tcpip benchmark::benchmark)
