# Vagrant Linux on macOS

This directory contains Vagrant configuration for running various Linux distributions to test osquery binaries. Currently it is designed to use macOS on Apple Silicon as the Host OS.

Guest OSes range from Ubuntu 16-24 and CentOS 6-10 on both x86 and aarch64.

## Prerequisites

- [Vagrant](https://www.vagrantup.com/downloads)
- [VirtualBox](https://www.virtualbox.org/wiki/Downloads)
- [QEMU](https://www.qemu.org/download)

Install required Vagrant plugins:

```bash
vagrant plugin install vagrant-qemu
vagrant plugin install virtualbox
```

## Usage

On a well-specced Macbook Pro, I am able to spin up many VMs at once (for example, all x86):

```bash
vagrant status | grep x86 | awk '{print $1}' | xargs -P0 -I {} vagrant up {}
```

Change `grep x86` to `grep arm` or any other target you'd like. Note that standard `vagrant up` does not run in parallel with the qemu or Virtualbox providers so is much slower than this approach with `xargs -P0`.

The contents of this directory are synced into the `/vagrant` directory of the VM when it is started. If you put an osqueryd binary in this directory, you can then try executing it on each of the running VMs:

```bash
vagrant status | grep running | cut -d ' ' -f1 | xargs -P0 -I {} vagrant ssh {} -c "/vagrant/osqueryd -S 'select * from os_version'"
```

Remember that each architecture needs a different osqueryd binary.
