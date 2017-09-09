osquery may optionally use a kernel extension (on macOS)/module (Linux) to introspect into process and socket events. This extends osquery by enabling more tables.

Currently an kernel extension is under development for macOS. Once the macOS implementation is finished a Linux module will be considered. There are several options for retrieving real time process and socket events. User-land implementation are preferred to having kernel presence.

> NOTICE: This is currently under heavy development.

The osquery kernel introspection architecture is designed with simplicity and portability. It uses a small ring buffer, backed by shared memory, filled by kernel callback registrations to maintain simple structures. A process creation structure may contain a path to the program image, assigned pid, and ownership information. When the ring buffer fills, osquery drops information. The user-land process, osqueryd, will periodically request a minimum and maximum read into the ring buffer and pass structures to an event subscriber.

This code is mostly shared between BSD-based kernels and Linux. The ring buffer uses spin locks to reserve structure blocks and synchronize simple writes. The minimum and maximum block reads are synchronized and reserved using an `ioctl` API and `/dev/osquery` device node. Each platform uses respective APIs to register callback methods that implement the ring buffer reserve, copy, and write.

The kernel applies calling-process ownership limitations to super users. Only 1 process should issues IOCTL commands, if another process (pid) uses the device node the queue and buffer are considered invalid and all pointers are reset. Clean tear down assures deregistration of callback functions and will result in maximum performance. Improper tear down may trigger timeouts and in the worst scenario continue to track callbacks.

To build the daemon with support for the kernel extensions use:
```
SKIP_KERNEL=0
make
```

# Apple Kernel Extensions

Kernel extension loading requires extension bundles signed by valid Apple developer certificates. During development it is NOT recommended to sign inline with building and running unit/integration tests. Changes to the kernel-mode code may result in kernel panics. Some of the development-only-enabled unit test code is designed to stress the limits of kernel memory management and event synchronization. It is very highly recommended to restrict these tests to running inside a virtual environment.

The high-level kernel development workflow involves:
- Install a copy of macOS in VMware and share a development/source/build folder.
- Compile and build the user-land and kernel-land code on your host.
- Load the kernel extension in the VM and run the kernel-specific unit tests.
- You may optionally configure the VM to break on boot to debug with `lldb`.

## Building on macOS for local loading (not recommended)

First disable signature verification on the machine by running `make kernel-deps` a reboot is required for this to take effect.  **CAUTION:** this lowers the security of your system.  It is better to have your kernel extensions signed on your host and develop/load in a virtual machine.

```
export SKIP_KERNEL=0
make kernel-build
make kernel-test-load
# Optionally run the unit tests
# make kernel-test
make kernel-test-unload
```

> NOTICE: do not deploy a kernel built with `make kernel-build` as it is designed for testings. Always deploy artifacts generated through `make packages`.

## Building on macOS for a debugging target machine (recommended)

You may configure your host and virtual machine for kernel and extension debugging. This involves a few extra steps beyond building, loading, and running tests.

- Get a [kernel debug kit](https://developer.apple.com/downloads/) from Apple's macOS Developer portal.
- Install it on both the target machine VM and the host debugging machine.
- Run make targets to configure the target machine and the debugger machine.
  - `make kernel-configure-target`  (on VM, requires a reboot)
  - `make kernel-debug` (on host)
- Connect to VM using the `kdp-remote <ip-address>` command.
- Load the kext on the host using `make kernel-load` target.


