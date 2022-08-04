# Building osquery's Third-party libraries

This folder contains all the third party libraries that osquery needs.
All the third party libraries in this folder are built from source.

The ones under `source` use CMake as the build system and they are brought in as submodules.
Their configuration logic is not run, so that their build is always the same, no matter the version of the platform they are built on.  
To achieve that, we generate and save their configuration artifacts in these folders, in a way that depends on each platform, but the general idea is that we want to have compatibility with the oldest version of the platform we want to support.

Finally, since we don't want to run their configuration logic and build system when building osquery, we write a CMakeLists.txt which builds the sources for the library and hardcodes additional compiler options that are not included in the generated files, but that the original build system to the compiler invocation when building.

The ones under `formula` (currently OpenSSL only) will still use CMake to build, but it passes through a different build system, which CMake executes. They can be submodules or, as in the case of OpenSSL, archives that CMake takes care to download.
This is because reproducing that build system with CMake has proven to be too complex.
Particular care is needed for these libraries, as with the `source` ones, so that they do not directly depend on features that are present only on the system they are currently built on.

## Linux

Beyond what previously described, we use a custom toolchain ([osquery-toolchain](https://github.com/osquery/osquery-toolchain)) that permits us to build osquery on either new distros or the oldest targeted distro (bar some bugs, see later).

These are the current targeted versions:

### x86

CentOS 6.10

```sh
cat /etc/centos-release
CentOS release 6.10 (Final)
```

```sh
ldd --version
ldd (GNU libc) 2.12
[...]
```

```sh
yum info glibc

[...]
Version: 2.12
Release: 1.212.el6_10.3
[...]
```

```sh
uname -r
2.6.32-754.18.2.el6.x86_64
```

### AArch64

Ubuntu 16.04 on AWS Graviton

```sh
cat /etc/os-release

[...]
VERSION="16.04.7 LTS (Xenial Xerus)"
[...]

```

```sh
ldd --version
ldd (Ubuntu GLIBC 2.23-0ubuntu11.3) 2.23
[...]
```

```sh
apt show libc-bin

[...]
Version: 2.23-0ubuntu11.3
[...]
```

```sh
uname -r
4.15.0-1099-aws
```

### Troubleshooting Linux

There are some issues with the osquery-toolchain 1.1.0 when trying to use it on CentOS 6.10.  
Binaries like `as`, `ar`, etc need to be symlinked to their llvm counterpart, since the original ones are fully static and contain a glibc version that won't work on that old distribution, and will throw a `FATAL: kernel too old`.  
To fix this, supposing that the osquery-toolchain has been installed under `/usr/local/osquery-toolchain`, run the following commands:

```sh
cd /usr/local/osquery-toolchain/usr/bin

rm as; ln -s llvm-as as
rm ar; ln -s llvm-ar ar
rm objcopy; ln -s llvm-objcopy objcopy
rm ranlib; ln -s llvm-ranlib ranlib
rm objdump; ln -s llvm-objdump objdump
rm nm; ln -s llvm-nm nm
rm strip; ln -s llvm-strip strip
```

## macOS

The system used to compile is currently macOS Big Sur 11.x, XCode 13.x, SDK 11.3.

Both x86_64 and ARM architectures of the executable are built on an x86_64 machine, using the toolchain's ability to cross-compile.

### macos x86_64

The deployment target is 10.14.

### macOS ARM (M1, M2, etc.)

The deployment target is 10.15.

## Windows

The system compiler is used on Windows 10, Visual Studio 2019.  
The SDK used currently is not fixed (depends on what's available on the CI or the developer machine), but in general the target we attempt to have is Windows 7.
