# libudev

## Linux

Using Ubuntu 14.04 (glibc 2.12)

```sh
ldd --version
ldd (GNU libc) 2.12.2
```

You will need to install:

```sh
sudo apt-get install gtk-doc-tools gperf
```

Generated with the following commands:

```sh
export PATH=/usr/local/osquery-toolchain/usr/bin:$PATH
export CFLAGS="--sysroot /usr/local/osquery-toolchain"
export CXXFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS}"
export CC=clang

./autogen.sh
./configure --enable-static --without-selinux --enable-gtk-doc-html=no --disable-gudev --disable-introspection
```

You should see output similar to:

```text
        udev 174
        ========

        prefix:                 /usr
        sysconfdir:             ${prefix}/etc
        sbindir:                ${exec_prefix}/sbin
        libdir:                 ${exec_prefix}/lib
        rootlibdir:             ${exec_prefix}/lib
        libexecdir:             ${exec_prefix}/libexec
        datarootdir:            ${prefix}/share
        mandir:                 ${datarootdir}/man
        includedir:             ${prefix}/include
        include_prefix:         /usr/include
        systemdsystemunitdir:
        firmware path:          \"/lib/firmware/updates/\", \"/lib/firmware/\"

        compiler:               clang
        cflags:                 --sysroot /usr/local/osquery-toolchain
        ldflags:                --sysroot /usr/local/osquery-toolchain
        xsltproc:               /usr/bin/xsltproc
        gperf:                  /usr/bin/gperf

        logging:                yes
        debug:                  no
        selinux:                no

        gudev:                  no
        gintrospection:         no
        keymap:                 yes
        hwdb:                   yes
          usb.ids:              /var/lib/usbutils/usb.ids
          pci.ids:              /usr/share/misc/pci.ids
        mtd_probe:              yes
        rule_generator:         no
        udev_acl:               no
        floppy:                 no
        edd:                    no
```

Then copy

```sh
cp ./config.h ../config/config.h
```
