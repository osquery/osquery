# libarchive

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

autoreconf -f -i
./configure --enable-static --without-lzo2 --without-nettle --without-xml2 --with-openssl --with-expat --enable-static
```

Then copy

```sh
cp ./config.h ../config/linux/config.h
```

Then turn on the following defines

- `HAVE_LIBLZMA`
- `HAVE_LZMA_H`
- `HAVE_LZMA_STREAM_ENCODER_MT`
- `HAVE_BZLIB_H`
- `HAVE_LIBBZ2`
- `HAVE_LIBXML2`
