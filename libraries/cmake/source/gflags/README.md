# gflags

Notes to reproduce the library configuration and generated files

## Linux

Using CentOS 6.10 (glibc 2.12)

```sh
ldd --version
ldd (GNU libc) 2.12
```

Install CMake

```sh
wget https://cmake.org/files/v3.17/cmake-3.17.5-Linux-x86_64.tar.gz
sudo tar xvf cmake-3.17.5-Linux-x86_64.tar.gz -C /usr/local --strip 1
```

Install the osquery toolchain

```sh
wget https://github.com/osquery/osquery-toolchain/releases/download/1.1.0/osquery-toolchain-1.1.0-x86_64.tar.xz
sudo tar xvf osquery-toolchain-1.1.0-x86_64.tar.xz -C /usr/local
```

Configure with
```sh
cmake ../ -DCMAKE_BUILD_TYPE=Release -DBUILD_gflags_LIB=ON -DBUILD_gflags_nothreads_LIB=OFF -DGFLAGS_NAMESPACE=gflags -DCMAKE_SYSROOT=/usr/local/osquery-toolchain -DCMAKE_CXX_COMPILER=/usr/local/osquery-toolchain/usr/bin/clang++
```


## Windows

Configure with

```sh
cmake -G "Visual Studio 16 2019" -A x64 ../ -DBUILD_gflags_LIB=ON -DBUILD_gflags_nothreads_LIB=OFF -DGFLAGS_NAMESPACE=gflags
```


## macOS

Configure with

```sh
cmake ../ -DCMAKE_BUILD_TYPE=Release -DBUILD_gflags_LIB=ON -DBUILD_gflags_nothreads_LIB=OFF -DGFLAGS_NAMESPACE=gflags
```


## All platforms

Copy the generated files under `include` from the build folder, to the respective folders in the osquery source under `libraries/cmake/source/gflags/generated`

Copy only once (it's the same for all platforms)

```
include/gflags/gflags_completions.h -> generated/gflags/gflags_completions.h
```

Then copy for each os

```
include/gflags/defines.h -> generated/<os>/private/defines.h
include/gflags/gflags_declare.h -> generated/<os>/public/gflags/gflags_declare.h
include/gflags/gflags.h -> generated/<os>/public/gflags/gflags.h
```
