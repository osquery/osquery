# librdkafka library build notes

## Linux

### Common

Make sure you are working in a clean source folder:

```bash
git reset --hard ; git clean -ffdx
```

Make sure that `libsasl2` is not enabled:

```bash
sed 's/set(WITH_SASL_CYRUS ON)/set(WITH_SASL_CYRUS OFF)/g' -i CMakeLists.txt
sed -i '/list(APPEND BUILT_WITH "SASL_CYRUS")/d' -i CMakeLists.txt
```

Integrate the osquery-toolchain in the main `CMakeLists.txt` file (see the following file in osquery: `cmake/toolchain.cmake`). Then configure the project:

```bash
cmake \
  -S . \
  -B build \
  -DOSQUERY_TOOLCHAIN_SYSROOT=/usr/local/osquery-toolchain \
  -DBUILD_SHARED_LIBS=OFF \
  -DENABLE_DEVEL=OFF \
  -DENABLE_LZ4_EXT=OFF \
  -DENABLE_REFCNT_DEBUG=OFF \
  -DRDKAFKA_BUILD_EXAMPLES=OFF \
  -DRDKAFKA_BUILD_STATIC=ON \
  -DRDKAFKA_BUILD_TESTS=OFF \
  -DWITHOUT_OPTIMIZATION=OFF \
  -DWITH_PLUGINS=ON \
  -DWITH_SASL=ON \
  -DWITH_SSL=ON \
  -DWITH_ZLIB=ON \
  -DWITH_ZSTD=ON \
  -DWITH_SASL_SCRAM:BOOL=ON \
  -DWITH_SASL_OAUTHBEARER:BOOL=ON
```

Build the project:

```bash
cmake \
  --build build
```

Copy the generated config file: `build/generated/config.h`

## macOS

Make sure you are working in a clean source folder:

```bash
git reset --hard ; git clean -ffdx
```

Make sure that `libsasl2` is not enabled:

```bash
gsed 's/set(WITH_SASL_CYRUS ON)/set(WITH_SASL_CYRUS OFF)/g' -i CMakeLists.txt
gsed -i '/list(APPEND BUILT_WITH "SASL_CYRUS")/d' -i CMakeLists.txt
```

### macOS x86_64

```sh
cmake \
  -S . \
  -B build \
  -DBUILD_SHARED_LIBS=OFF \
  -DENABLE_DEVEL=OFF \
  -DENABLE_LZ4_EXT=OFF \
  -DENABLE_REFCNT_DEBUG=OFF \
  -DRDKAFKA_BUILD_EXAMPLES=OFF \
  -DRDKAFKA_BUILD_STATIC=ON \
  -DRDKAFKA_BUILD_TESTS=OFF \
  -DWITHOUT_OPTIMIZATION=OFF \
  -DWITH_PLUGINS=ON \
  -DWITH_SASL=ON \
  -DWITH_SSL=ON \
  -DWITH_ZLIB=ON \
  -DWITH_ZSTD=ON \
  -DWITH_SASL_SCRAM:BOOL=ON \
  -DWITH_SASL_OAUTHBEARER:BOOL=ON \
  -DCMAKE_OSX_SYSROOT=/Applications/Xcode_13.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=10.14 \
  -DCMAKE_OSX_ARCHITECTURES=x86_64 \
  -DOPENSSL_ROOT_DIR=/usr/local/Cellar/openssl@1.1/1.1.1k
```

### macOS ARM (M1, M2, etc.)

```sh
cmake \
  -S . \
  -B build \
  -DBUILD_SHARED_LIBS=OFF \
  -DENABLE_DEVEL=OFF \
  -DENABLE_LZ4_EXT=OFF \
  -DENABLE_REFCNT_DEBUG=OFF \
  -DRDKAFKA_BUILD_EXAMPLES=OFF \
  -DRDKAFKA_BUILD_STATIC=ON \
  -DRDKAFKA_BUILD_TESTS=OFF \
  -DWITHOUT_OPTIMIZATION=OFF \
  -DWITH_PLUGINS=ON \
  -DWITH_SASL=ON \
  -DWITH_SSL=ON \
  -DWITH_ZLIB=ON \
  -DWITH_ZSTD=ON \
  -DWITH_SASL_SCRAM:BOOL=ON \
  -DWITH_SASL_OAUTHBEARER:BOOL=ON \
  -DCMAKE_OSX_SYSROOT=/Applications/Xcode_13.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15 \
  -DCMAKE_OSX_ARCHITECTURES=arm64 \
  -DOPENSSL_ROOT_DIR=/usr/local/Cellar/openssl@1.1/1.1.1k
```

## Windows

```cmd
cmake ^
  -S . ^
  -B build ^
  -DBUILD_SHARED_LIBS=OFF ^
  -DENABLE_DEVEL=OFF ^
  -DENABLE_LZ4_EXT=OFF ^
  -DENABLE_REFCNT_DEBUG=OFF ^
  -DRDKAFKA_BUILD_EXAMPLES=OFF ^
  -DRDKAFKA_BUILD_STATIC=ON ^
  -DRDKAFKA_BUILD_TESTS=OFF ^
  -DWITHOUT_OPTIMIZATION=OFF ^
  -DWITH_PLUGINS=ON ^
  -DWITH_SASL=ON ^
  -DWITH_SSL=ON ^
  -DWITH_ZLIB=ON ^
  -DWITH_ZSTD=ON ^
  -DWITH_SASL_SCRAM:BOOL=ON ^
  -DWITH_SASL_OAUTHBEARER:BOOL=ON
```
