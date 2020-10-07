# libcryptsetup

## Linux

Using Ubuntu 14.04 (glibc 2.12)

```sh
ldd --version
ldd (GNU libc) 2.12.2
```

You will need the `uuid/uuid.h` header installed:

```sh
sudo apt-get install uuid-dev libdevmapper-dev
```

Generated with the following commands:

```sh
./autogen.sh
./configure --enable-static --disable-selinux --disable-udev --disable-veritysetup --disable-kernel_crypto
```

Then copy

```sh
cp ./config.h ../config/config.h
```

Set the following defines:

- `#define USE_INTERNAL_PBKDF2 0`

