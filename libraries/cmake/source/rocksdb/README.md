# rocksdb library build notes

## Windows

### Windows x86_64

```sh
cmake ^
  -DCMAKE_BUILD_TYPE=RelWithDebInfo ^
  -S . ^
  -B build ^
  -G Ninja ^
  -DFAIL_ON_WARNINGS=OFF ^
  -DROCKSDB_BUILD_SHARED=OFF ^
  -DROCKSDB_LITE=OFF ^
  -DWITH_ALL_TESTS=OFF ^
  -DWITH_BENCHMARK_TOOLS=OFF ^
  -DWITH_CORE_TOOLS=OFF ^
  -DWITH_GFLAGS=OFF ^
  -DWITH_TOOLS=OFF ^
  -DWITH_PERF_CONTEXT=OFF ^
  -DPORTABLE=ON
```

## Linux

Make sure to use the osquery-toolchain so that settings are correctly detected. You will have to edit the main CMakeLists.txt of RocksDB. Take a look at `cmake/toolchain.cmake` to see how to do it.

### Linux x86_64

```sh
cmake \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -S . \
  -B build \
  -G Ninja \
  -DFAIL_ON_WARNINGS=OFF \
  -DROCKSDB_BUILD_SHARED=OFF \
  -DROCKSDB_LITE=OFF \
  -DWITH_ALL_TESTS=OFF \
  -DWITH_BENCHMARK_TOOLS=OFF \
  -DWITH_CORE_TOOLS=OFF \
  -DWITH_GFLAGS=OFF \
  -DWITH_TOOLS=OFF \
  -DWITH_PERF_CONTEXT=OFF \
  -DPORTABLE=ON \
  -DFORCE_SSE42=ON \
  -DWITH_LIBURING=OFF
```

### Linux AArch64

```bash
cmake \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -S . \
  -B build \
  -G Ninja \
  -DFAIL_ON_WARNINGS=OFF \
  -DROCKSDB_BUILD_SHARED=OFF \
  -DROCKSDB_LITE=OFF \
  -DWITH_ALL_TESTS=OFF \
  -DWITH_BENCHMARK_TOOLS=OFF \
  -DWITH_CORE_TOOLS=OFF \
  -DWITH_GFLAGS=OFF \
  -DWITH_TOOLS=OFF \
  -DWITH_PERF_CONTEXT=OFF \
  -DWITH_LIBURING=OFF \
  -DPORTABLE=ON \
  -DHAS_ARMV8_CRC:BOOL=OFF \
  -DWITH_IOSTATS_CONTEXT=OFF
```

## macOS

### macOS x86_64

```sh
cmake \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -S . \
  -B build \
  -G Ninja \
  -DFAIL_ON_WARNINGS=OFF \
  -DROCKSDB_BUILD_SHARED=OFF \
  -DROCKSDB_LITE=OFF \
  -DWITH_ALL_TESTS=OFF \
  -DWITH_BENCHMARK_TOOLS=OFF \
  -DWITH_CORE_TOOLS=OFF \
  -DWITH_GFLAGS=OFF \
  -DWITH_TOOLS=OFF \
  -DWITH_PERF_CONTEXT=OFF \
  -DPORTABLE=ON \
  -DFORCE_SSE42=ON \
  -DCMAKE_OSX_SYSROOT=/Applications/Xcode_13.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=10.14 \
  -DCMAKE_OSX_ARCHITECTURES=x86_64
```

### macOS ARM (M1, M2, etc.)

```sh
cmake \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -S . \
  -B build \
  -G Ninja \
  -DFAIL_ON_WARNINGS=OFF \
  -DROCKSDB_BUILD_SHARED=OFF \
  -DROCKSDB_LITE=OFF \
  -DWITH_ALL_TESTS=OFF \
  -DWITH_BENCHMARK_TOOLS=OFF \
  -DWITH_CORE_TOOLS=OFF \
  -DWITH_GFLAGS=OFF \
  -DWITH_TOOLS=OFF \
  -DWITH_PERF_CONTEXT=OFF \
  -DPORTABLE=ON \
  -DHAVE_SSE42:BOOL=OFF \
  -DWITH_IOSTATS_CONTEXT=OFF \
  -DCMAKE_OSX_SYSROOT=/Applications/Xcode_13.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15 \
  -DCMAKE_OSX_ARCHITECTURES=arm64
```
