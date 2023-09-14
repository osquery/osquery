# libmagic library build notes

## macOS

Install the required build-time dependencies:

```bash
brew install \
  autoconf \
  automake \
  libtool
```

Prepare the environment:

Note: If building for macOS ARM, substitute the target with `-target arm64-apple-macos10.15` at the end of the `CFLAGS` environment variable.

```bash
export CC=clang
export OSQUERY_LZMA_HEADER="/Users/<user>/osquery/src/libraries/cmake/source/lzma/src/src/liblzma/api"
export CFLAGS="-isysroot /Applications/Xcode_14.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX13.3.sdk -I${OSQUERY_LZMA_HEADER} -target x86_64-apple-macos10.15"
```

Configure and build the project:

Note: If building for macOS ARM, add `--host=arm64-apple-macos10.15` at the end of the configure invocation (otherwise the configure will fail, trying to launch an ARM binary locally).

```bash
autoreconf \
  -f \
  -i
```

```bash
./configure \
  --disable-shared \
  --enable-static \
  --with-pic \
  --disable-libseccomp \
  --disable-bzlib

make -j $(nproc)
```

## Linux

### Common

Prepare the environment

```bash
export OSQUERY_LZMA_HEADER="/home/<user>/osquery/src/libraries/cmake/source/lzma/src/src/liblzma/api"
export PATH="/usr/local/osquery-toolchain/usr/bin:${PATH}"
export CFLAGS="--sysroot /usr/local/osquery-toolchain -I${OSQUERY_LZMA_HEADER}"
export CXXFLAGS="${CFLAGS}"
export CPPFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS}"
export CC=clang
```

Configure and build the project

```bash
autoreconf \
  -f \
  -i

./configure \
  --disable-shared \
  --enable-static \
  --with-pic \
  --disable-libseccomp \
  --disable-bzlib

make -j $(nproc)
```

NOTE: if the autoreconf step fails with `configure.ac:97: error: required file './ltmain.sh' not found` run `libtoolize` and then the autoreconf command again.

## All Platforms

Make sure that these defines are enabled in the config.h file:

```text
#define HAVE_LIBZ 1
#define HAVE_LZMA_H 1
#define XZLIBSUPPORT 1
```

If XZLIBSUPPORT is not 1, just enable it in the config.h; the configure script only tests for the presence of a function,
so if it's needed and it's missing from the version osquery is building, linking will fail anyway.

Copy the generated config file for each platform:

`config.h` -> `config/<os>/<arch>/`

Copy only once:

`src/magic.h` -> `include/`
