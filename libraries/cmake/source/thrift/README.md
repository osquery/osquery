# thrift

## Linux

Using Ubuntu 14.04 (glibc 2.12)

```sh
ldd --version
ldd (GNU libc) 2.12.2
```

Generated with the following commands:

```sh
export PATH=/usr/local/osquery-toolchain/usr/bin:$PATH
export CFLAGS="--sysroot /usr/local/osquery-toolchain"
export CXXFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS}"
export CC=clang
export CXX=clang++

./bootstrap.sh
# We do not want boost because thrift will used stdc++ instead.
./configure --enable-static --without-python --with-cpp --with-libevent=no --enable-tutorial=no --with-boost=no
```

Then copy

```
cp ./config.h ../config/linux/thrift/config.h
```

Finally, update `PACKAGE_VERSION` within `CMakeLists.txt`.

