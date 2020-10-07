# libdpkg

## Linux

Using Ubuntu 14.04 (glibc 2.12)

```sh
ldd --version
ldd (GNU libc) 2.12.2
```

Install a newer version of `gettext`:

```sh
wget http://de.archive.ubuntu.com/ubuntu/pool/main/g/gettext/autopoint_0.19.7-2ubuntu3_all.deb
sudo dpkg -i autopoint_0.19.7-2ubuntu3_all.deb
```

If you have an older version of `perl`:

```
sudo apt-get install perlbrew
mkdir -p /home/ubuntu/perl5/perlbrew/dists
mkdir -p /home/ubuntu/perl5/perlbrew/build
wget https://www.cpan.org/src/5.0/perl-5.20.2.tar.bz2
mv perl-5.20.2.tar.bz2 /home/ubuntu/perl5/perlbrew/dists
perlbrew --notest install perl-5.20.2
```

You may also need this patch:

```diff
diff --git a/configure.ac b/configure.ac
index d6c80d7..4eb5855 100644
--- a/configure.ac
+++ b/configure.ac
@@ -3,7 +3,7 @@
 m4_pattern_forbid([^_?DPKG_])
 
 AC_PREREQ(2.60)
-AC_INIT([dpkg], m4_esyscmd([./get-version]), [debian-dpkg@lists.debian.org])
+AC_INIT([dpkg], 1.19.0.5, [debian-dpkg@lists.debian.org])
 AC_SUBST([PACKAGE_COPYRIGHT_HOLDER], ['Dpkg Developers'])
 AC_CONFIG_SRCDIR([lib/dpkg/dpkg.h])
 AC_CONFIG_MACRO_DIR([m4])
```

Generated with the following commands:

```sh
export PATH=/home/ubuntu/perl5/perlbrew/perls/perl-5.20.2/bin/:$PATH
export PATH=/usr/local/osquery-toolchain/usr/bin:$PATH
export CFLAGS="--sysroot /usr/local/osquery-toolchain"
export CXXFLAGS="${CFLAGS}"
export LDFLAGS="${CFLAGS}"
export CC=clang
export CXX=clang++

autoreconf -f -i
./configure --enable-static --disable-devel-docs --disable-dselect --disable-start-stop-daemon --without-libselinux
```

Then copy

```sh
cp ./config.h ../config/x86_64/config.h
```

We can turn on support for LZMA and BZ2 by defining:

- `WITH_LIBBZ2`
- `WITH_LIBLZMA`
- `WITH_LIBZ`
