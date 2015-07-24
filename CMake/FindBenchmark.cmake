set(BENCHMARK_SOURCE_DIR "${CMAKE_SOURCE_DIR}/third-party/benchmark")
set(BENCHMARK_BUILD_DIR "${CMAKE_BINARY_DIR}/third-party/benchmark")

# Only build the benchmark shared library for benchmark targets.
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "")

INCLUDE_DIRECTORIES("${BENCHMARK_SOURCE_DIR}/include")
ADD_SUBDIRECTORY("${BENCHMARK_SOURCE_DIR}")
