# glog

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
cmake ../ -DCMAKE_BUILD_TYPE=Release -DWITH_TLS=OFF -DWITH_GFLAGS=OFF -DWITH_THREADS=ON -DHAVE_LIB_GFLAGS=ON -DCMAKE_SYSROOT=/usr/local/osquery-toolchain -DCMAKE_CXX_COMPILER=/usr/local/osquery-toolchain/usr/bin/clang++ -DCMAKE_C_COMPILER=/usr/local/osquery-toolchain/usr/bin/clang -DCMAKE_C_FLAGS="-pthread" -DCMAKE_CXX_FLAGS="-pthread"
```


## Windows

Configure with

```sh
cmake -G "Visual Studio 16 2019" -A x64 ../ -DWITH_TLS=OFF -DWITH_GFLAGS=OFF -DWITH_THREADS=ON -DHAVE_LIB_GFLAGS=ON
```


## macOS

Configure with

```sh
cmake ../ -DCMAKE_BUILD_TYPE=Release -DWITH_TLS=OFF -DWITH_GFLAGS=OFF -DWITH_THREADS=ON -DHAVE_LIB_GFLAGS=ON
```


## All platforms

Copy the generated files from the build folder, to the respective folders in the osquery source under `libraries/cmake/source/glog/generated`

```
glog -> libraries/cmake/source/glog/generated/<os>/public/glog
config.h -> libraries/cmake/source/glog/generated/<os>/private/config.h
```

Edit `TEST_SRC_DIR` in `generated/<os>/private/config.h` and set it to `""`, since it's not necessary
