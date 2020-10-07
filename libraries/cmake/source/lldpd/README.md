# lldpd

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
./configure --enable-static
make
```

Then copy

```sh
cp ./libevent/include/event2/event-config.h ../config/ARCH/linux/libevent/event2
cp ./libevent/config.h ../config/ARCH/linux/libevent
cp ./config.h ../config/ARCH/linux/liblldpd
cp ./src/lib/atom-glue.c ../generated/linux/src/lib
```

Then set in `config/ARCH/linux/liblldpd/config.h` set:

- `BUILD_DATE` to `""`
- `PRIVSEP_CHROOT` to `/var/empty`
- `PRIVSEP_GROUP` to `nogroup`
- `PRIVSEP_USER` to `nobody`
