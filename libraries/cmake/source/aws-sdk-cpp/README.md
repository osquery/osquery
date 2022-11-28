# aws-sdk-cpp library build notes

## Linux

### Common

Integrate the osquery toolchain in the main CMakeLists.txt file; you can use the `cmake/toolchain.cmake` include as a starting point.

```sh
cmake \
  -S . \
  -B build \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_BUILD_TYPE=Release \
  -DNO_HTTP_CLIENT=ON \
  -DOSQUERY_TOOLCHAIN_SYSROOT=/usr/local/osquery-toolchain
```

## macOS

### macOS x86_64

```sh
cmake \
  -S . \
  -B build \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_BUILD_TYPE=Release \
  -DNO_HTTP_CLIENT=ON \
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
  -DCMAKE_BUILD_TYPE=Release \
  -DNO_HTTP_CLIENT=ON \
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
  -DCMAKE_BUILD_TYPE=Release ^
  -DNO_HTTP_CLIENT=ON
```
