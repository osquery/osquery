# zlib library build notes

Check that the defines we are hardcoding in the CMakeLists.txt corresponds to the ones that are enabled during compilation.
Also verify that if there are preprocessors `#if/#ifdef` checks in `zconf.h` that are modified to `#if 1`,
the respective define checked is also present among the defines we are hardcoding.

For instance if
```
#ifdef HAVE_UNISTD_H    /* may be set to #if 1 by ./configure */
#  define Z_HAVE_UNISTD_H
#endif
```

becomes
```
#if 1    /* was set to #if 1 by ./configure */
#  define Z_HAVE_UNISTD_H
#endif
```

Add `HAVE_UNISTD_H` in the hardcoded defines.

On Windows, when using CMake to configure, the `zconf.h` file is in the build folder, and it should be compared with the `zconf.h.included` file in the source folder.

## Linux

### Linux x86_64/AArch64

Generated with the following commands:

```bash
export TOOLCHAIN=/usr/local/osquery-toolchain
export PATH="${TOOLCHAIN}/usr/bin:${PATH}"
export CFLAGS="--sysroot ${TOOLCHAIN}"
export CXXFLAGS="${CFLAGS}"
export CPPFLAGS="${CFLAGS}"
export CC=clang

./configure --static --64
make
```

## macOS

Generated with the following commands:

### macOS ARM (M1, M2, etc.)

```sh
export CFLAGS="-isysroot /Applications/Xcode_15.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.2.sdk -target arm64-apple-macos10.15"
./configure --static --64
make
```

### macOS x86-64

```sh
export CFLAGS="-isysroot /Applications/Xcode_15.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX14.2.sdk -target x86_64-apple-macos10.15"
./configure --static --64
make
```

## Windows

Generated with the following commands:

### Windows x86-64

```sh
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
mkdir build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="cl.exe" -S . -B build
cmake --build build --verbose
```

### Windows arm64

Prepare a `cross.cmake` file with
```cmake
set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR ARM64)
```

Then to configure:

```sh
call "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" x64_arm64
mkdir build
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="cl.exe" -DCMAKE_TOOLCHAIN_FILE=cross.cmake -S . -B build
cmake --build build --verbose
```
