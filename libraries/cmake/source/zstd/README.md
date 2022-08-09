# zstd library build notes

## Linux

### Common

Make sure you are working on a clean source folder

```bash
git reset --hard ; git clean -ffdx
```

Integrate the osquery-toolchain in the main CMakeLists.txt file (see the following file in osquery: `cmake/toolchain.cmake`). Then configure the project.

```sh
cmake \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -S build/cmake \
  -B build/cmake/output \
  -G Ninja \
  -DOSQUERY_TOOLCHAIN_SYSROOT=/usr/local/osquery-toolchain \
  -DZSTD_BUILD_CONTRIB=OFF \
  -DZSTD_BUILD_PROGRAMS=OFF \
  -DZSTD_BUILD_SHARED=OFF \
  -DZSTD_BUILD_STATIC=ON \
  -DZSTD_BUILD_TESTS=OFF \
  -DZSTD_LEGACY_SUPPORT=OFF \
  -DZSTD_LZMA_SUPPORT=OFF \
  -DZSTD_MULTITHREAD_SUPPORT=ON \
  -DZSTD_ZLIB_SUPPORT=OFF
```

Build the project

```bash
cmake \
  --build build \
  -j $(nproc)
```

## macOS

### Intel, Apple Silicon

TARGET: Either x86_64 or arm64
DEPLOYMENT: 10.14 for x86_64, 10.15 for arm64

```sh
cmake \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_OSX_ARCHITECTURES=<TARGET> \
  -DCMAKE_OSX_SYSROOT=/Applications/Xcode_13.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk \
  -DCMAKE_OSX_DEPLOYMENT_TARGET=<DEPLOYMENT> \
  -S build/cmake \
  -B build/cmake/output \
  -G Ninja \
  -DZSTD_BUILD_CONTRIB=OFF \
  -DZSTD_BUILD_PROGRAMS=OFF \
  -DZSTD_BUILD_SHARED=OFF \
  -DZSTD_BUILD_STATIC=ON \
  -DZSTD_BUILD_TESTS=OFF \
  -DZSTD_LEGACY_SUPPORT=OFF \
  -DZSTD_LZMA_SUPPORT=OFF \
  -DZSTD_MULTITHREAD_SUPPORT=ON \
  -DZSTD_ZLIB_SUPPORT=OFF
```

## Windows

```sh
cmake ^
  -G "Visual Studio 16 2019" ^
  -A x64 ^
  -S build/cmake ^
  -B build/cmake/output ^
  -DZSTD_BUILD_CONTRIB=OFF ^
  -DZSTD_BUILD_PROGRAMS=OFF ^
  -DZSTD_BUILD_SHARED=OFF ^
  -DZSTD_BUILD_STATIC=ON ^
  -DZSTD_BUILD_TESTS=OFF ^
  -DZSTD_LEGACY_SUPPORT=OFF ^
  -DZSTD_MULTITHREAD_SUPPORT=ON ^
```
