# librpm

## Linux

You will need to build the following osquery targets first: thirdparty_popt, thirdparty_libmagic, thirdparty_lzma, thirdparty_sqlite, thirdparty_zlib, thirdparty_zstd, openssl.

Then create the following symlinks for each library, excluded openssl (run from the build folder):

```
ln -s libthirdparty_popt.a libs/src/popt/libpopt.a
ln -s libthirdparty_libmagic.a libs/src/libmagic/libmagic.a
ln -s libthirdparty_lzma.a libs/src/lzma/liblzma.a
ln -s libthirdparty_sqlite.a libs/src/sqlite/src/libsqlite.a
ln -s libthirdparty_zlib.a libs/src/zlib/libz.a
ln -s libthirdparty_zstd.a libs/src/zstd/libzstd.a
```


Then:
1. Copy the build folder to the target machine and point the `LIBS_BUILD` env var to it
2. Clone the latest version of osquery to the target machine and point the `LIBS_SRC` env var to it
3. Copy the patches under `libraries/cmake/source/librpm/build-patches` and `libraries/cmake/source/librpm/patches` to the target machine
4. Move inside the librpm source code and apply with `git apply` the patches

Then run the following commands:

```sh
export TOOLCHAIN=/usr/local/osquery-toolchain
export PKG_CONFIG_LIBDIR=${TOOLCHAIN}/usr/lib/pkgconfig
export PKG_CONFIG_PATH=
export PKG_CONFIG_SYSROOT_DIR=${TOOLCHAIN}
export OPENSSL_INCLUDE="${LIBS_BUILD}/openssl/openssl-prefix/src/openssl/include"
export OPENSSL_LINK="${LIBS_BUILD}/openssl/openssl-prefix/src/openssl"
export LIBMAGIC_INCLUDE="${LIBS_SRC}/libraries/cmake/source/libmagic/include"
export LIBMAGIC_LINK="${LIBS_BUILD}/libs/src/libmagic"
export POPT_INCLUDE="${LIBS_SRC}/libraries/cmake/source/popt/src/src"
export POPT_LINK="${LIBS_BUILD}/libs/src/popt"
export ZLIB_INCLUDE="${LIBS_SRC}/libraries/cmake/source/zlib/src"
export ZLIB_LINK="${LIBS_BUILD}/libs/src/zlib"
export LZMA_INCLUDE="${LIBS_SRC}/libraries/cmake/source/lzma/src/src/liblzma/api"
export LZMA_LINK="${LIBS_BUILD}/libs/src/lzma"
export SQLITE_LIBS="-L${LIBS_BUILD}/libs/src/sqlite/src -lsqlite"
export SQLITE_CFLAGS="-I${LIBS_SRC}/libraries/cmake/source/sqlite/src/src"
export ZSTD_LIBS="-L${LIBS_BUILD}/libs/src/zstd -lzstd"
export ZSTD_CFLAGS="-I${LIBS_SRC}/libraries/cmake/source/zstd/src/lib"
export CFLAGS="--sysroot ${TOOLCHAIN} -I${OPENSSL_INCLUDE} -I${LIBMAGIC_INCLUDE} -I${POPT_INCLUDE} -I${ZLIB_INCLUDE} -I${LZMA_INCLUDE}"
export CPPFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS} -L${OPENSSL_LINK} -L${LIBMAGIC_LINK} -L${POPT_LINK} -L${ZLIB_LINK} -L${LZMA_LINK}"
export CC=${TOOLCHAIN}/usr/bin/clang
export LIBS="-llzma -lz -lrt"

autoreconf -i
./configure \
  --enable-static \
  --disable-shared \
  --with-crypto=openssl \
  --without-archive \
  --enable-bdb-ro \
  --enable-sqlite \
  --enable-ndb \
  --disable-plugins \
  --disable-openmp \
  --disable-libelf
```

Then copy these files to the osquery source

`./config.h` -> `config/<arch>/config.h`
`./lib/rpmhash.C` -> `/generated/<arch>/lib/`

Run `make` and then copy this additional generated file:

`./lib/tagtbl.C` -> `generated/<arch>/lib/`

## Linux x86_64

Make sure that the `config.h` file does not have defined `HAVE_SECURE_GETENV`, `HAVE_GETAUXVAL`, and `HAVE_SYNCFS`.

### Additional Notes

The build time patch is required to have the configure.ac script work with the version of GETTEXT it's present on CentOS 6.
Furthermore, librpm has removed the ability to disable the use of Lua, which is not useful for osquery, since we only want to read, so we have to patch it out.

Finally there are two additional patches which are instead applied when we build osquery.
One, the `remove-lua.patch`, which only touches source code, is a part of the bigger build patch. So when having to update this first generate the build patch, then remove the parts from it that touch build files and the result is this patch.

To regenerate the `centos6-support-and-remove-lua.patch`, make all the necessary changes to the build files and then use `git diff -- '*.ac' '*.am'`.
To regenerate the `remove-lua.patch` make all the necessary changes to the source code to remove lua and then use `git diff -- '*.c' '*.h'`.
To regenerate the `open-only-pkgs.patch`, the idea is to only open the Packages database, which in the current version can be done by setting the `justPkgs` to 1.
