# popt

## Linux

Patch the configure.ac file to use the gettext version 0.17 on the system; also remove the unsupported usage of `AM_GNU_GETTEXT_REQUIRE_VERSION`

```sh
sed -i 's/0\.19\.8/0\.17/g' configure.ac
sed -i '/AM_GNU_GETTEXT_REQUIRE_VERSION/d' configure.ac
```

Generated with the following commands:

```sh
export TOOLCHAIN=/usr/local/osquery-toolchain
export PKG_CONFIG_LIBDIR=${TOOLCHAIN}/usr/lib/pkgconfig
export PKG_CONFIG_PATH=
export PKG_CONFIG_SYSROOT_DIR=${TOOLCHAIN}
export CFLAGS="--sysroot ${TOOLCHAIN}"
export CXXFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS}"
export CC="${TOOLCHAIN}/usr/bin/clang"

./autogen.sh
./configure --disable-shared --enable-static
```

Then build with:

```
make
```

And keep track of the preprocessor defines used, which will have to be put in our CMakeLists.txt

Then copy

```sh
cp ./config.h ../config/linux/config.h
```
