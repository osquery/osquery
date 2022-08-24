# lzma library build notes

## Linux

### Linux x86

Download the tarball version.

Generate with the following commands:

```bash
export PATH=/usr/local/osquery-toolchain/usr/bin:$PATH
export CFLAGS="--sysroot /usr/local/osquery-toolchain"
export CXXFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS}"
export CC=clang

./configure --disable-xz --disable-xzdec --disable-lzmadec --disable-lzma-links --disable-scripts --disable-doc --enable-static --enable-encoders=lzma1,lzma2,x86,arm,armthumb,delta --enable-decoders=lzma1,lzma2,x86,arm,armthumb,delta --disable-nls
```

### Linux AArch64

Install:

```bash
sudo apt install autoconf automake libtool
```

Generate with the following commands:

```bash
export PATH=/usr/local/osquery-toolchain/usr/bin:$PATH
export CFLAGS="--sysroot /usr/local/osquery-toolchain"
export CXXFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS}"
export CC=clang

./autogen.sh
./configure --disable-xz --disable-xzdec --disable-lzmadec --disable-lzma-links --disable-scripts --disable-doc --enable-static --enable-encoders=lzma1,lzma2,x86,arm,armthumb,delta --enable-decoders=lzma1,lzma2,x86,arm,armthumb,delta --disable-nls
```

### Linux Common

Then copy:

```sh
cp ./config.h ../config/linux/<arch>/config.h
```

To the build also add the defines:

```text
HAVE_CONFIG_H
TUKLIB_SYMBOL_PREFIX=lzma_
```

## macOS

Generated with the following commands:

### macOS ARM (M1, M2, etc.)

```sh
./autogen.sh
export CFLAGS="-isysroot /Applications/Xcode_13.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk -target arm64-apple-macos10.15"
./configure --disable-xz --disable-xzdec --disable-lzmadec --disable-lzma-links --disable-scripts --disable-doc --disable-shared --enable-static --enable-encoders=lzma1,lzma2,x86,arm,armthumb,delta --enable-decoders=lzma1,lzma2,x86,arm,armthumb,delta --disable-nls --host=aarch64-apple-darwin
```

### macOS x86_64

```sh
./autogen.sh
CFLAGS="-isysroot /Applications/Xcode_13.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk -target x86_64-apple-macos10.14"
./configure --disable-xz --disable-xzdec --disable-lzmadec --disable-lzma-links --disable-scripts --disable-doc --disable-shared --enable-static --enable-encoders=lzma1,lzma2,x86,arm,armthumb,delta --enable-decoders=lzma1,lzma2,x86,arm,armthumb,delta --disable-nls
```

### macOS Common

Then copy:

```sh
cp ./config.h ../config/macos/<arch>/config.h
```

To the build also add the defines:

```text
HAVE_CONFIG_H
TUKLIB_SYMBOL_PREFIX=lzma_
```

## Windows

Copy `windows\vs2019\config.h` from the `lzma` source to `config\x86_64\windows`.

Then comment these defines inside the `config.h` file:

```text
#define HAVE_DECODER_IA64 1
#define HAVE_DECODER_POWERPC 1
#define HAVE_DECODER_SPARC 1

#define HAVE_ENCODER_IA64 1
#define HAVE_ENCODER_POWERPC 1
#define HAVE_ENCODER_SPARC 1
```

From the build we also add the defines:

```text
HAVE_CONFIG_H
TUKLIB_SYMBOL_PREFIX=lzma_
LZMA_API_STATIC
```
