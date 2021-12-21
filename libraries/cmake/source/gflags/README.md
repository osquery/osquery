# Linux

## x86

Configure with
```sh
cmake ../ -DCMAKE_BUILD_TYPE=Release -DBUILD_gflags_LIB=ON -DBUILD_gflags_nothreads_LIB=OFF -DGFLAGS_NAMESPACE=gflags -DCMAKE_SYSROOT=/usr/local/osquery-toolchain -DCMAKE_CXX_COMPILER=/usr/local/osquery-toolchain/usr/bin/clang++
```

## AArch64

Configure with
```sh
cmake ../ -DCMAKE_BUILD_TYPE=Release -DBUILD_gflags_LIB=ON -DBUILD_gflags_nothreads_LIB=OFF -DGFLAGS_NAMESPACE=gflags -DCMAKE_SYSROOT=/usr/local/osquery-toolchain -DCMAKE_CXX_COMPILER=/usr/local/osquery-toolchain/usr/bin/clang++
```

# Windows

Configure with

```sh
cmake -G "Visual Studio 16 2019" -A x64 ../ -DBUILD_gflags_LIB=ON -DBUILD_gflags_nothreads_LIB=OFF -DGFLAGS_NAMESPACE=gflags
```


# macOS

Generated with the following commands:

## M1

```sh
cmake ../ -DCMAKE_BUILD_TYPE=Release -DBUILD_gflags_LIB=ON -DBUILD_gflags_nothreads_LIB=OFF -DGFLAGS_NAMESPACE=gflags -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15 -DCMAKE_OSX_ARCHITECTURES=arm64
```


## x86

```sh
cmake ../ -DCMAKE_BUILD_TYPE=Release -DBUILD_gflags_LIB=ON -DBUILD_gflags_nothreads_LIB=OFF -DGFLAGS_NAMESPACE=gflags -DCMAKE_OSX_DEPLOYMENT_TARGET=10.12
```


# All platforms

Copy the generated files under `include` from the build folder, to the respective folders in the osquery source under `libraries/cmake/source/gflags/generated`

Copy only once (it's the same for all platforms)

```
include/gflags/gflags_completions.h -> generated/gflags/gflags_completions.h
```

Then copy for each os

```
include/gflags/defines.h -> generated/<os>/<arch>/private/defines.h
include/gflags/gflags_declare.h -> generated/<os>/<arch>/public/gflags/gflags_declare.h
include/gflags/gflags.h -> generated/<os>/<arch>/public/gflags/gflags.h
```
