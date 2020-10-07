# librdkafka

## Linux

Using Ubuntu 14.04 (glibc 2.12)

```sh
ldd --version
ldd (GNU libc) 2.12.2
```

Generated with the following commands:

```sh
export OPENSSL_INCLUDE=../../../../../build/openssl/openssl-prefix/src/openssl/include
export OPENSSL_LINK=../../../../../build/openssl/openssl-prefix/src/openssl
export PATH=/usr/local/osquery-toolchain/usr/bin:$PATH
export CFLAGS="--sysroot /usr/local/osquery-toolchain -I$OPENSSL_INCLUDE"
export CXXFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS} -L$OPENSSL_LINK"
export CC=clang
export CXX=clang++

./configure --enable-ssl --disable-gssapi --enable-sasl --disable-lz4 --disable-lz4-ext --enable-static
```

Then copy

```sh
cp ./config.h ../config/ARCH/linux/
```
