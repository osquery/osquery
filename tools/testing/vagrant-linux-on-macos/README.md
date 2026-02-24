# Vagrant Linux on macOS

This directory contains Vagrant configuration for running various Linux distributions to test osquery binaries. Currently it is designed to use macOS on Apple Silicon as the Host OS.

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

Start up all defined VMs (there are a lot!):

```bash
vagrant up
```

Start up only ubuntu:

```bash
vagrant up '/ubuntu.*/'
```

```bash
vagrant status | grep running | cut -d ' ' -f1 | xargs -I {} vagrant ssh {} -c "/vagrant/osqueryd -S 'select * from os_version'"
```
