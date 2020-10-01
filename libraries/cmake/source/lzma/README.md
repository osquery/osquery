# lzma

## Linux

Using Ubuntu 14.04 (glibc 2.12)

```sh
ldd --version
ldd (GNU libc) 2.12.2
```

Generated with the following commands:

```sh
export PATH=/usr/local/osquery-toolchain/usr/bin:$PATH
export CFLAGS="--sysroot /usr/local/osquery-toolchain"
export CXXFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS}"
export CC=clang

./autogen.sh
./configure --disable-xz --disable-xzdec --disable-lzmadec --disable-lzma-links --disable-scripts --disable-doc --enable-static --enable-encoders=lzma1,lzma2,x86,arm,armthumb
```

Then copy

```sh
cp ./config.h ../config/ARCH/linux/config.h
```
