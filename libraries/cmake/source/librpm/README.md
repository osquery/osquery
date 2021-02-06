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
sudo apt-get install libmagic-dev libpopt-dev autopoint zlib1g-dev
```

And you will need a "built" version of osquery in `./build` to find/use our exact OpenSSL version.

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
./configure --enable-static --with-crypto=openssl --without-archive --enable-bdb --enable-bdb-ro --enable_sqlite --without-lua --disable-plugins --disable-openmp
```

Then copy

```sh
cp ./config.h ../config/config.h
cp ./lib/rpmhash.C ../generated/lib/
```

Run `make` and then copy the include files:

```sh
cp -R ./include ../
cp ./lib/tagtbl.C ../generated/lib/
```

And set (in the appropriate places):

```sh
#define HAVE_LZMA_H 1
#define HAVE_ZSTD 1
```

Make sure `secure_getenv`, `getauxval`, and `syncfs` are not found.
