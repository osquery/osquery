# smartmontools

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
./configure --disable-scripts --disable-doc --enable-static --without-nvme-devicescan
```

You should see something similar to:

```text
smartmontools-6.6 configuration:
host operating system:  x86_64-unknown-linux-gnu
C++ compiler:           g++
C compiler:             clang
preprocessor flags:
C++ compiler flags:     --sysroot /usr/local/osquery-toolchain -Wall -W
C compiler flags:       --sysroot /usr/local/osquery-toolchain
linker flags:           --sysroot /usr/local/osquery-toolchain
OS specific modules:    os_linux.o cciss.o dev_areca.o
binary install path:    /usr/local/sbin
man page install path:  /usr/local/share/man
doc file install path:  /usr/local/share/doc/smartmontools
examples install path:  /usr/local/share/doc/smartmontools/examplescripts
drive database file:    /usr/local/share/smartmontools/drivedb.h
database update script: /usr/local/sbin/update-smart-drivedb
download tools:         curl wget lynx svn
GnuPG for verification: gpg
local drive database:   /usr/local/etc/smart_drivedb.h
smartd config file:     /usr/local/etc/smartd.conf
smartd warning script:  /usr/local/etc/smartd_warning.sh
smartd plugin path:     /usr/local/etc/smartd_warning.d
PATH within scripts:    /usr/bin:/bin
smartd initd script:    /usr/local/etc/init.d/smartd.initd
smartd save files:      [disabled]
smartd attribute logs:  [disabled]
libcap-ng support:      no
SELinux support:        no
NVMe DEVICESCAN:        no
```

Then copy

```sh
cp ./config.h ../config/ARCH/linux/config.h
```

You can set `SMARTMONTOOLS_CONFIGURE_ARGS` to a blank string.
