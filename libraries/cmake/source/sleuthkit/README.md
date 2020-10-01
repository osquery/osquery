# sleuthkit

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

./bootstrap
./configure --disable-scripts --disable-doc --enable-static --disable-java
```

You should see:

```text
Building:
   afflib support:                        no
   libewf support:                        no
   zlib support:                          yes
   libvhdi support:                       no
   libvmdk support:                       no
   postgresql support:                    no
Features:
   Java/JNI support:                      no
   Multithreading:                        yes
```

Then copy

```sh
cp ./tsk/tsk_config.h ../config/linux/tsk/tsk_config.h
cp ./tsk/tsk_incs.h ../config/linux/tsk/tsk_incs.h
```
