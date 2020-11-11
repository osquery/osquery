# libdevmapper

## Linux

Using Ubuntu 14.04 (glibc 2.12)

```sh
ldd --version
ldd (GNU libc) 2.12.2
```

You will need more autoconf macros:

```sh
sudo apt-get install autoconf-archive
```

Generated with the following commands:

```sh
export PATH=/usr/local/osquery-toolchain/usr/bin:$PATH
export CFLAGS="--sysroot /usr/local/osquery-toolchain"
export CXXFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS}"
export CC=clang
export CXX=clang++

autoreconf -f -i
./configure --with-lvm1=none --disable-selinux --disable-readline --enable-static_link
```

Then copy

```sh
cp ./include/lvm-version.h ../include/lvm-version.h
cp ./include/configure.h ../config/configure.h
cp ./lib/config/config.h ../config/config.h
```
