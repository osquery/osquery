# libelfin

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
export CXX=clang++

make
```

Then copy

```sh
cp ./elf/to_string.cc ../generated/elf
cp ./dwarf/to_string.cc ../generated/dwarf
```

You can delete the `Automatically generated at DELETEME` timestamp.
