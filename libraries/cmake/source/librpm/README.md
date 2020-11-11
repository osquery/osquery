# librpm

## Linux

Using Ubuntu 14.04 (glibc 2.12)

```sh
ldd --version
ldd (GNU libc) 2.12.2
```

This is generally difficult to install.

You will need to install:

```sh
sudo apt-get install libmagic-dev libpopt-dev
```

Generated with the following commands:

```sh
export OPENSSL_INCLUDE=../../../../../build/openssl/openssl-prefix/src/openssl/include
export OPENSSL_LINK=../../../../../build/openssl/openssl-prefix/src/openssl
export LIBMAGIC_INCLUDE=../../libmagic/include
export LIBMAGIC_LINK=/usr/lib/x86_64-linux-gnu
export POPT_INCLUDE=../../popt/src
export POPT_LINK=/usr/lib/x86_64-linux-gnu
export PATH=/usr/local/osquery-toolchain/usr/bin:$PATH
export CFLAGS="--sysroot /usr/local/osquery-toolchain -I$OPENSSL_INCLUDE -I$LIBMAGIC_INCLUDE -I$POPT_INCLUDE"
export CPPFLAGS="${CFLAGS}"
export CXXFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS} -L$OPENSSL_LINK -L$LIBMAGIC_LINK -L$POPT_LINK"
export CC=clang

./autogen.sh
./configure --enable-static --with-crypto=openssl --without-archive --enable-bdb=no --without-lua --disable-plugins --disable-openmp
```

Then copy

```sh
cp ./config.h ../config/config.h
```

And set (in the appropriate places):

```sh
#define HAVE_DB_H 1
#define WITH_BDB 1
#define HAVE_LZMA_H 1
#define HAVE_ZSTD 1
```

Make sure `secure_getenv`, `getauxval`, and `syncfs` are not found.
