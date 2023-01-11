# yara

## Linux, macOS

You will need to have the osquery source code on the machine used for configuring and build the following osquery targets first: thirdparty_libmagic, thidparty_lzma, thirdparty_zlib, openssl.

Then create the following symlinks for each library, excluded openssl (run from the build folder):

```sh
ln -s libthirdparty_libmagic.a libs/src/libmagic/libmagic.a
ln -s libthirdparty_lzma.a libs/src/lzma/liblzma.a
ln -s libthirdparty_zlib.a libs/src/zlib/libz.a
```

Then set the `LIBS_SRC` and `LIBS_BUILD` to the respective osquery source and build folder.

## Linux

Then prepare the environment with:

```sh
export TOOLCHAIN=/usr/local/osquery-toolchain
export PKG_CONFIG_LIBDIR=${TOOLCHAIN}/usr/lib/pkgconfig
export PKG_CONFIG_PATH=
export PKG_CONFIG_SYSROOT_DIR=${TOOLCHAIN}
export OPENSSL_INCLUDE="${LIBS_BUILD}/openssl/openssl-prefix/src/openssl/include"
export OPENSSL_LINK="${LIBS_BUILD}/openssl/openssl-prefix/src/openssl"
export LIBMAGIC_INCLUDE="${LIBS_SRC}/libraries/cmake/source/libmagic/include"
export LIBMAGIC_LINK="${LIBS_BUILD}/libs/src/libmagic"
export ZLIB_INCLUDE="${LIBS_SRC}/libraries/cmake/source/zlib/src"
export ZLIB_LINK="${LIBS_BUILD}/libs/src/zlib"
export LZMA_INCLUDE="${LIBS_SRC}/libraries/cmake/source/lzma/src/src/liblzma/api"
export LZMA_LINK="${LIBS_BUILD}/libs/src/lzma"
export CFLAGS="--sysroot ${TOOLCHAIN} -I${OPENSSL_INCLUDE} -I${LIBMAGIC_INCLUDE} -I${LZMA_INCLUDE}"
export CPPFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS} -L${OPENSSL_LINK} -L${LIBMAGIC_LINK} -L${LZMA_LINK}"
export CC=${TOOLCHAIN}/usr/bin/clang
```

On aarch64 use `export LIBS="-llzma -lz -ldl"` on x86_64 use `export LIBS="-llzma -lz -ldl -lrt"`

Then configure with:

```sh
./bootstrap.sh
./configure \
  --disable-shared \
  --enable-static \
  --enable-magic \
  --enable-dex \
  --enable-macho
```

And build with:
```sh
make -j$(nproc) V=1
```

## macOS

Then prepare the environment with:

```sh
export OPENSSL_INCLUDE="${LIBS_BUILD}/openssl/openssl-prefix/src/openssl/include"
export OPENSSL_LINK="${LIBS_BUILD}/openssl/openssl-prefix/src/openssl"
export LIBMAGIC_INCLUDE="${LIBS_SRC}/libraries/cmake/source/libmagic/include"
export LIBMAGIC_LINK="${LIBS_BUILD}/libs/src/libmagic"
export ZLIB_INCLUDE="${LIBS_SRC}/libraries/cmake/source/zlib/src"
export ZLIB_LINK="${LIBS_BUILD}/libs/src/zlib"
export LZMA_INCLUDE="${LIBS_SRC}/libraries/cmake/source/lzma/src/src/liblzma/api"
export LZMA_LINK="${LIBS_BUILD}/libs/src/lzma"
export CC=clang
export LIBS="-llzma -lz"
```

On x86_64 use:

```sh
export CFLAGS="-isysroot /Applications/Xcode_13.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk -target x86_64-apple-macos10.14 -I${OPENSSL_INCLUDE} -I${LIBMAGIC_INCLUDE} -I${LZMA_INCLUDE}"
```

On arm64 use:

```sh
export CFLAGS="-isysroot /Applications/Xcode_13.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk -target arm64-apple-macos10.15 -I${OPENSSL_INCLUDE} -I${LIBMAGIC_INCLUDE} -I${LZMA_INCLUDE}"
```

And then:

```sh
export CPPFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS} -L${OPENSSL_LINK} -L${LIBMAGIC_LINK} -L${LZMA_LINK}"
```

Then on x86_64 configure with:

```sh
./bootstrap.sh
./configure \
  --disable-shared \
  --enable-static \
  --enable-magic \
  --enable-dex \
  --enable-macho
```

On arm64 use:

```sh
./bootstrap.sh
./configure \
  --disable-shared \
  --enable-static \
  --enable-magic \
  --enable-dex \
  --enable-macho \
  --host=arm64-apple-darwin19.0.0
```

And build with:

```sh
make -j$(nproc) V=1
```

## Windows

Refer to the `libyara.vcxproj` file in `windows/vs2017`.

## Linux, macOS

Look at the `config.log` file, at the end where there are the preprocessor defines in `confdefs.h`. These should be used in our CMakeLists.txt, but we can skip all the `PACKAGE*` ones, `VERSION` and `LT_OBJDIR`.
While not all remaining defines are used, for simplicity we keep them. Additionally look at the `Output variables` section and the `CFLAGS` variable content, adding those preprocessor defines too.
Finally check the verbose build output to see if there are additional preprocessor defines not seen anywhere else, like `_GNU_SOURCE`.

## Additional notes

A patch to `strutils.c` is required since we normally want to rename common functions like `strlcat` and `strlcpy` if they are needed and implemented by the library itself. Since we do that with a preprocessor define and since the `strutils.c` not only checks for `!HAVE_STRLCAT` but also `!defined(strlcat)` before implementing the function, we need to remove the second check, otherwise it won't be implemented (because already defined by our preprocessor trick, although there's no actual function with that name being compiled in).
