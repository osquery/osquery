# Linux

## Common

### Update the system

#### x86

Enable the package archives

```bash
sed -i -e 's/^mirrorlist/#mirrorlist/g' -e 's/^#baseurl=http:\/\/mirror.centos.org\/centos\/$releasever\//baseurl=http:\/\/vault.centos.org\/6.10\//g' /etc/yum.repos.d/CentOS-Base.repo
```

Update the installed packages

```bash
yum update
```

#### AArch64

Update the installed packages

```bash
apt update
apt upgrade -y
```


### Install build dependencies (AArch64 only)

```bash
apt install -y make \
               m4
```

### Initialize the environment (x86 + AArch64)

```bash
export TOOLCHAIN=/usr/local/osquery-toolchain
export PATH="${TOOLCHAIN}/usr/bin:${PATH}"
export CFLAGS="--sysroot ${TOOLCHAIN}"
export CXXFLAGS="${CFLAGS}"
export CPPFLAGS="${CFLAGS}"
export CC=clang
```

### Install perl (x86 + AArch64)

```bash
curl https://www.cpan.org/src/5.0/perl-5.34.1.tar.gz -L -O
tar xzf perl-5.34.1.tar.gz
```

Then, run the `./Configure` script and follow the instructions. Make sure to pass `clang` as compiler.

### Install autoconf (x86 + AArch64)

```bash
curl https://ftp.gnu.org/gnu/autoconf/autoconf-2.71.tar.xz -L -O
tar xf autoconf-2.71.tar.xz
```

```bash
./configure --prefix=/usr
make -j $(nproc)
make install
```

### Install automake (x86 + AArch64)

```bash
curl https://ftp.gnu.org/gnu/automake/automake-1.16.5.tar.xz -L -O
tar xf automake-1.16.5.tar.xz
```

```bash
./configure --prefix=/usr
make -j $(nproc)
make install
```

### Install libtool (x86 + AArch64)

```bash
curl https://ftpmirror.gnu.org/libtool/libtool-2.4.6.tar.gz -L -O
tar xzf libtool-2.4.6.tar.gz
```

```bash
./configure --prefix=/usr
make -j $(nproc)
make install
```

### Install gettext (x86 + AArch64)

```bash
curl https://ftp.gnu.org/pub/gnu/gettext/gettext-0.21.tar.gz -L -O
tar xfz gettext-0.21.tar.gz
```

```bash
./configure --prefix=/usr
make -j $(nproc)
make install
```

### Install pkg-config (AArch64)

```bash
https://pkgconfig.freedesktop.org/releases/pkg-config-0.29.2.tar.gz -L -O
tar xzf pkg-config-0.29.2.tar.gz
```

```bash
./configure --prefix=/usr --with-internal-glib
make -j $(nproc)
make install
```

### Install Python 3.6 (x86 only)

Enable the SCL:

```bash
yum install centos-release-scl
```

Update the repository file: `/etc/yum.repos.d/CentOS-SCLo-scl.repo`

```
[centos-sclo-sclo]
name=CentOS-6 - SCLo sclo
baseurl=https://vault.centos.org/centos/6.10/sclo/x86_64/rh
# baseurl=http://mirror.centos.org/centos/6/sclo/$basearch/sclo/
# mirrorlist=http://mirrorlist.centos.org?arch=$basearch&release=6&repo=sclo-sclo
gpgcheck=1
enabled=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-CentOS-SIG-SCLo
```

```bash
yum install rh-python36-python
```

Enable Python 3.5

```bash
scl enable rh-python36 bash
```

### Build the osquery dependencies: zlib, liblzma, libbz2 (x86 + AArch64)

1. Install CMake and configure osquery
2. Build the following targets: `thirdparty_zlib`, `thirdparty_lzma`, `thirdparty_bzip2`

```bash
cmake --build build --target thirdparty_zlib thirdparty_lzma thirdparty_bzip2
```

Update the environment

```bash
export OSQUERY_SOURCE_ROOT=/path/to/osquery/source/directory
export OSQUERY_BUILD_ROOT=/path/to/osquery/build/directory
```

Rename the libraries to their real names:

```bash
ln -sf "${OSQUERY_BUILD_ROOT}/libs/src/bzip2/libthirdparty_bzip2.a" "${OSQUERY_BUILD_ROOT}/libs/src/bzip2/libbz2.a"
ln -sf "${OSQUERY_BUILD_ROOT}/libs/src/zlib/libthirdparty_zlib.a" "${OSQUERY_BUILD_ROOT}/libs/src/zlib/libz.a"
ln -sf "${OSQUERY_BUILD_ROOT}/libs/src/lzma/libthirdparty_lzma.a" "${OSQUERY_BUILD_ROOT}/libs/src/lzma/liblzma.a"
```

Open the `CMakeLists.txt` files for each library, and take note of the `SYSTEM INTERFACE` include directories:

 * zlib: `${OSQUERY_SOURCE_ROOT}/libraries/cmake/source/zlib/src`
 * bzip2: `${OSQUERY_SOURCE_ROOT}/libraries/cmake/source/bzip2/src`
 * liblzma: `${OSQUERY_SOURCE_ROOT}/libraries/cmake/source/lzma/src/src/liblzma/api`

### Build libdpkg

Update the environment we prepared previously, so that it can link back to the osquery dependencies that we have just built. Variable names are important when it comes to the library paths; make sure to checkout the output of `./configure --help`.

```bash
export PKG_CONFIG_LIBDIR=${TOOLCHAIN}/usr/lib/pkgconfig
export PKG_CONFIG_PATH=
export PKG_CONFIG_SYSROOT_DIR=${TOOLCHAIN}

export ZLIB_INCLUDE="${OSQUERY_SOURCE_ROOT}/libraries/cmake/source/zlib/src"
export BZ2_INCLUDE="${OSQUERY_SOURCE_ROOT}/libraries/cmake/source/bzip2/src"
export LZMA_INCLUDE="${OSQUERY_SOURCE_ROOT}/libraries/cmake/source/lzma/src/src/liblzma/api"

export Z_LIBS="-L${OSQUERY_BUILD_ROOT}/libs/src/zlib -lz"
export BZ2_LIBS="-L${OSQUERY_BUILD_ROOT}/libs/src/bzip2 -lbz2"
export LZMA_LIBS="-L${OSQUERY_BUILD_ROOT}/libs/src/lzma -llzma"

export CFLAGS="--sysroot ${TOOLCHAIN} -I${ZLIB_INCLUDE} -I${BZ2_INCLUDE} -I${LZMA_INCLUDE}"
export CPPFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS} ${Z_LIBS} ${BZ2_LIBS} ${LZMA_LIBS}"

export CC=${TOOLCHAIN}/usr/bin/clang
```

Generate the configure script

```bash
autoreconf -f -i
```

The configure script may fail if the `patch --version` output does not contain the `GNU patch` string at the start of a new line. Update the check to just look for GNU, since we already know we have a good `patch` binary.

```bash
sed -i 's/\^GNU patch/GNU/g' configure
```

```bash
./configure --enable-static --disable-devel-docs --disable-dselect --disable-start-stop-daemon --with-liblzma --with-libz --with-libbz2 --without-libselinux --without-libz-ng --without-libmd
```
