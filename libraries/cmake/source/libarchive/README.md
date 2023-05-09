# libarchive library build notes

## Linux

Integrate the osquery-toolchain, using the following file as a starting point: `cmake/toolchain.cmake`. Pass the toolchain like this: `-DOSQUERY_TOOLCHAIN_SYSROOT=/usr/local/osquery-toolchain`

## macOS

Append the following to the CMake options:

### macOS x86-64

```bash
-DCMAKE_OSX_SYSROOT=/Applications/Xcode_13.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk -DCMAKE_OSX_DEPLOYMENT_TARGET=10.14 -DCMAKE_OSX_ARCHITECTURES=x86_64
```

### macOS ARM (M1, M2, etc.)

```bash
-DCMAKE_OSX_SYSROOT=/Applications/Xcode_13.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk -DCMAKE_OSX_DEPLOYMENT_TARGET=10.15 -DCMAKE_OSX_ARCHITECTURES=arm64
```

## Linux/macOS

```sh
cmake \
  -S . \
  -B b \
  -DBUILD_TESTING=OFF \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_BZip2=OFF \
  -DENABLE_LIBXML2=OFF \
  -DENABLE_LZMA=OFF \
  -DENABLE_OPENSSL=OFF \
  -DENABLE_ZLIB=OFF \
  -DENABLE_ZSTD=OFF \
  -DENABLE_ACL=OFF \
  -DENABLE_CAT=OFF \
  -DENABLE_CAT_SHARED=OFF \
  -DENABLE_CNG=OFF \
  -DENABLE_COVERAGE=OFF \
  -DENABLE_CPIO=OFF \
  -DENABLE_CPIO_SHARED=OFF \
  -DENABLE_EXPAT=OFF \
  -DENABLE_ICONV=OFF \
  -DENABLE_INSTALL=OFF \
  -DENABLE_LIBB2=OFF \
  -DENABLE_LZ4=OFF \
  -DENABLE_LZO=OFF \
  -DENABLE_LIBGCC=OFF \
  -DENABLE_MBEDTLS=OFF \
  -DENABLE_NETTLE=OFF \
  -DENABLE_PCREPOSIX=OFF \
  -DENABLE_SAFESEH=AUTO \
  -DENABLE_TAR=OFF \
  -DENABLE_TAR_SHARED=OFF \
  -DENABLE_TEST=OFF \
  -DENABLE_WERROR=OFF \
  -DENABLE_XATTR=OFF
```

## Windows (x86-64, ARM64)

```cmd
cmake ^
  -S . ^
  -B b ^
  -DBUILD_TESTING=OFF ^
  -DBUILD_SHARED_LIBS=OFF ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DENABLE_BZip2=OFF ^
  -DENABLE_LIBXML2=OFF ^
  -DENABLE_LZMA=OFF ^
  -DENABLE_OPENSSL=OFF ^
  -DENABLE_ZLIB=OFF ^
  -DENABLE_ZSTD=OFF ^
  -DENABLE_ACL=OFF ^
  -DENABLE_CAT=OFF ^
  -DENABLE_CAT_SHARED=OFF ^
  -DENABLE_CNG=OFF ^
  -DENABLE_COVERAGE=OFF ^
  -DENABLE_CPIO=OFF ^
  -DENABLE_CPIO_SHARED=OFF ^
  -DENABLE_EXPAT=OFF ^
  -DENABLE_ICONV=OFF ^
  -DENABLE_INSTALL=OFF ^
  -DENABLE_LIBB2=OFF ^
  -DENABLE_LZ4=OFF ^
  -DENABLE_LZO=OFF ^
  -DENABLE_LIBGCC=OFF ^
  -DENABLE_MBEDTLS=OFF ^
  -DENABLE_NETTLE=OFF ^
  -DENABLE_PCREPOSIX=OFF ^
  -DENABLE_SAFESEH=AUTO ^
  -DENABLE_TAR=OFF ^
  -DENABLE_TAR_SHARED=OFF ^
  -DENABLE_TEST=OFF ^
  -DENABLE_WERROR=OFF ^
  -DENABLE_XATTR=OFF ^
  -DWINDOWS_VERSION=WIN7 ^
  -DPOSIX_REGEX_LIB=NONE
```

NOTE: If necessary, convert the config.h line endings from CRLF to LF.
The `POSIX_REGEX_LIB=NONE` is a hack, since it tries to find a library only if it's set to some other hardcoded values. For our use the regex library is currently not necessary, because it's only used by a CLI shipped with the libarchive project. Not doing so gives an error during configure time: `libgcc not found.`

## Common

After configuration, copy the config.h from the `b` folder.
