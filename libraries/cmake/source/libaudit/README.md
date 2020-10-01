# libaudit

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

./autogen.sh
./configure --enable-static --with-arm --with-aarch64
(cd lib && make)
```

Then copy

```sh
for header in aarch64_tables actiontabs arm_tables errtabs fieldtabs flagtabs ftypetabs gen_tables i386_tables ia64_tables machinetabs msg_typetabs optabs ppc_tables s390_tables s390x_tables x86_64_tables; \
 do cp ./lib/${header}.h ../generated/${header}.h; \
done

cp ./config.h ../config/ARCH/config.h
```
