Check that the generated `zconf.h` and the compilation enables the defines that we are hardcoding in the CMakeLists.txt.

# Linux

## x86

Generated with the following commands:

```bash
export PATH="${TOOLCHAIN}/usr/bin:${PATH}"
export CFLAGS="--sysroot ${TOOLCHAIN}"
export CXXFLAGS="${CFLAGS}"
export CPPFLAGS="${CFLAGS}"
export CC=clang

./configure --static --64
make
```

## AArch64

Generated with the following commands:

```bash
export PATH="/usr/local/osquery-toolchain/usr/bin:${PATH}"
export CFLAGS="--sysroot /usr/local/osquery-toolchain"
export CXXFLAGS="${CFLAGS}"
export CPPFLAGS="${CFLAGS}"
export CC=clang

./configure --static --64
make
```

# macOS

Generated with the following commands:

## M1

```sh
CFLAGS="-isysroot /Applications/Xcode_13.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk -target arm64-apple-macos10.15" ./configure --static --64
make
```

## x86

```sh
CFLAGS="-isysroot /Applications/Xcode_13.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk -target x86_64-apple-macos10.12"
./configure --static --64
make
```
