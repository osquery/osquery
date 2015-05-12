This is a work in progress as osquery builds kernel-level instrumentation. There
are three areas of work in the OS X and Linux kernels:

* Emitting kernel-only accessible eventing data like process and sockets
* Introspection into kernel-level integrity and data structures
* Userland process (osqueryd) protections

# Linux Kernel

osquery's first bit of linux kernel instrumentation consists of camb (pronounce <i>CAM-bee</i>), which is a kernel module that exposes via sysfs some kernel integrity information. It currently lives out-of-tree. The below guide has been tested on 64-bit Ubuntu, but "most likely works" with other distros with minor tweaking.

Build requirements:

1. Linux kernel headers
1. System.map file for a built kernel

Build steps:

```sh
$ git clone https://github.com/facebook/osquery.git
$ sudo apt-get install -y linux-headers-$(uname -r)
$ cd kernel/linux
$ sudo make SMAP=/boot/System.map-$(uname -r) KDIR=/lib/modules/$(uname -r)/build
```

Install steps:

```sh
$ sudo insmod camb.ko
```
