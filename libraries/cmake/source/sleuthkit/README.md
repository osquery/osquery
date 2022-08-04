# sleuthkit library build notes

## Linux

### Linux Common

Prepare the environment:

```bash
export PATH="/usr/local/osquery-toolchain/usr/bin:${PATH}"
export CFLAGS="--sysroot /usr/local/osquery-toolchain"
export CXXFLAGS="${CFLAGS}"
export CPPFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS} -lm"
export CC=clang
export CXX="clang++"
```

Make sure you are working in a clean source folder:

```bash
git reset --hard ; git clean -ffdx
```

Disable the `stdc++` library check:

```bash
sed -i '/stdc++/d' configure.ac
```

Disable tools, documentation, etc.:

```bash
sed -i '/SUBDIRS = tsk/c\SUBDIRS = tsk' Makefile.am
```

Configure the project:

```bash
./bootstrap

./configure \
  --enable-static \
  --disable-java \
  --without-libewf \
  --without-libvhdi \
  --without-libvmdk \
  --without-afflib
```

Expected output:

```text
Building:
   afflib support:                        no
   libewf support:                        no
   zlib support:                          yes

   libvhdi support:                       no
   libvmdk support:                       no
Features:
   Java/JNI support:                      no
   Multithreading:                        yes
```

Start the build

```bash
make -j $(nproc)
```

Copy the generated files: `tsk/tsk_config.h`, `tsk/tsk_incs.h`

## macOS

Make sure you are working in a clean repository:

```bash
git reset --hard ; git clean -ffdx
```

Once the `libtool` brew package has been installed:

```bash
mkdir bin
ln -s $(which glibtool) bin/libtool
ln -s $(which glibtoolize) bin/libtoolize

export PATH="$(pwd)/bin:${PATH}"
```

Update the `Makefile.am` file:

```patch
-SUBDIRS = tsk tools tests samples man $(UNIT_TESTS) $(JAVA_BINDINGS) $(JAVA_CASEUCO)
+SUBDIRS = tsk
```

Prepare the environment.

Note: If building for macOS ARM, change the target to `-target arm64-apple-macos10.15` at the end of the `CFLAGS` environment variable.

```bash
export CFLAGS="-isysroot /Applications/Xcode_13.0.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX11.3.sdk -target x86_64-apple-macos10.14"
export CXXFLAGS="${CFLAGS}"
```

Configure the project.

Note: If building for macOS ARM, add `--host=arm64-apple-macos10.15` at the end of the configure invocation (otherwise the configure will fail, trying to launch an M1 binary locally).

```bash
./bootstrap

./configure \
  --disable-shared \
  --enable-static \
  --disable-java \
  --without-libewf \
  --without-libvhdi \
  --without-libvmdk \
  --without-afflib
```

Expected output:

```text
Building:
   afflib support:                        no
   libewf support:                        no
   zlib support:                          yes

   libvhdi support:                       no
   libvmdk support:                       no
Features:
   Java/JNI support:                      no
   Multithreading:                        yes
```

Build the project:

```bash
make -j $(sysctl -n hw.logicalcpu)
```

Copy the generated files: `tsk/tsk_config.h`, `tsk/tsk_incs.h`

## Windows

The solution file under `src/win32/tsk-win.sln`, used to build and the various compiler options used, has been copied and hardcoded in our CMake.
