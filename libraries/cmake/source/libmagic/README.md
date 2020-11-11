# libmagic

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

autoreconf -f -i
./configure --enable-static
(cd ./src && make magic.h)
```

Then copy

```sh
cp ./config.h ../config/linux
cp ./src/magic.h ../include/magic.h
```
