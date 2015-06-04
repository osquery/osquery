#!/usr/bin/env bash

#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function install_gcc() {
  TARBALL=gcc-4.8.4.tar.gz
  URL=$DEPS_URL/gcc-4.8.4.tar.gz
  SOURCE=gcc-4.8.4
  TARGET=/opt/osquery/gcc

  if provision gcc $TARGET/bin/gcc4.8.4; then
    log "compiling a gcc toolchain, this may take a while..."
    TARGET_SOURCE=$SOURCE

    # GCC-dependency: GMP
    TARBALL=gmp-6.0.0a.tar.gz
    URL=$DEPS_URL/gmp-6.0.0a.tar.gz
    SOURCE=gmp-6.0.0
    if provision gmp $WORKING_DIR/$TARGET_SOURCE/gmp/README; then
      log "Moving gmp sources into $TARGET_SOURCE"
      cp -R $SOURCE $TARGET_SOURCE/gmp
    fi

    # GCC-dependency: MPFR
    TARBALL=mpfr-3.1.2.tar.gz
    URL=$DEPS_URL/mpfr-3.1.2.tar.gz
    SOURCE=mpfr-3.1.2
    if provision mpfr $WORKING_DIR/$TARGET_SOURCE/mpfr/README; then
      log "Moving mpfr sources into $TARGET_SOURCE"
      cp -R $SOURCE $TARGET_SOURCE/mpfr
    fi

    # GCC-dependency: MPC
    TARBALL=mpc-1.0.3.tar.gz
    URL=$DEPS_URL/mpc-1.0.3.tar.gz
    SOURCE=mpc-1.0.3
    if provision mpc $WORKING_DIR/$TARGET_SOURCE/mpc/README; then
      log "Moving mpc sources into $TARGET_SOURCE"
      cp -R $SOURCE $TARGET_SOURCE/mpc
    fi

    sudo mkdir -p $TARGET
    pushd $TARGET_SOURCE
    ./configure \
      --disable-checking \
      --enable-languages=c,c++ \
      --disable-multilib \
      --disable-multiarch \
      --enable-shared \
      --enable-threads=posix \
      --program-suffix=4.8.4 \
      --without-included-gettext \
      --prefix=$TARGET
    make -j $THREADS
    sudo make install

    [ -L /usr/bin/gcc ] && sudo unlink /usr/bin/gcc
    [ -L /usr/bin/g++ ] && sudo unlink /usr/bin/g++
    sudo ln -sf $TARGET/bin/gcc4.8.4 /usr/bin/gcc
    sudo ln -sf $TARGET/bin/g++4.8.4 /usr/bin/g++
    sudo ln -sf $TARGET/lib64/libstdc++.so.6.0.19 /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.19
    sudo ln -sf $TARGET/lib64/libstdc++.so.6.0.19 /usr/lib/x86_64-linux-gnu/libstdc++.so.6
    popd
  fi
}

function install_cmake() {
  TARBALL=cmake-3.2.1.tar.gz
  URL=$DEPS_URL/cmake-3.2.1.tar.gz
  SOURCE=cmake-3.2.1

  if provision cmake /usr/local/bin/cmake; then
    pushd $SOURCE
    ./bootstrap --prefix=/usr/local/
    # Note: this sometimes fails with an error about a missing libncurses
    # The solution is to run make deps again.
    CC="$CC" CXX="$CXX" make -j $THREADS
    sudo make install
    popd
  fi
}

function install_thrift() {
  TARBALL=0.9.1.tar.gz
  URL=$DEPS_URL/0.9.1.tar.gz
  SOURCE=thrift-0.9.1

  if provision thrift /usr/local/lib/libthrift.a; then
    pushd $SOURCE
    ./bootstrap.sh
    ./configure CFLAGS="$CFLAGS" \
      --with-cpp=yes \
      --with-python=yes \
      --with-ruby=no \
      --with-go=no \
      --with-erlang=no \
      --with-java=no \
      --with-php=no \
      --with-qt4=no \
      --with-qt=no
    CC="$CC" CXX="$CXX" make -j $THREADS
    sudo make install
    popd
  fi
}

function install_rocksdb() {
  TARBALL=rocksdb-3.10.2.tar.gz
  URL=$DEPS_URL/rocksdb-3.10.2.tar.gz
  SOURCE=rocksdb-rocksdb-3.10.2

  if provision rocksdb /usr/local/lib/librocksdb.a; then
    if [[ ! -f rocksdb-rocksdb-3.10.2/librocksdb.a ]]; then
      if [[ $FAMILY = "debian" ]]; then
        CLANG_INCLUDE="-I/usr/include/clang/3.4/include"
      elif [[ $FAMILY = "redhat" ]]; then
        CLANG_VERSION=`clang --version | grep version | cut -d" " -f3`
        CLANG_INCLUDE="-I/usr/lib/clang/$CLANG_VERSION/include"
      fi
      pushd $SOURCE
      if [[ $OS = "freebsd" ]]; then
        PORTABLE=1 CC=cc CXX=c++ gmake -j $THREADS static_lib \
          CFLAGS="$CLANG_INCLUDE $CFLAGS"
      else
        PORTABLE=1 CC="$CC" CXX="$CXX" make -j $THREADS static_lib \
          CFLAGS="$CLANG_INCLUDE $CFLAGS"
      fi
      popd
    fi
    sudo cp rocksdb-rocksdb-3.10.2/librocksdb.a /usr/local/lib
    sudo cp -R rocksdb-rocksdb-3.10.2/include/rocksdb /usr/local/include
  fi
}

function install_snappy() {
  TARBALL=snappy-1.1.1.tar.gz
  URL=$DEPS_URL/snappy-1.1.1.tar.gz
  SOURCE=snappy-1.1.1

  if provision snappy /usr/local/lib/libsnappy.a; then
    if [[ ! -f snappy-1.1.1/.libs/libsnappy.a ]]; then
      pushd $SOURCE
      CC="$CC" CXX="$CXX" ./configure --with-pic --enable-static
      make -j $THREADS
      popd
    fi
    # We do not need the snappy include headers, just static library.
    sudo cp snappy-1.1.1/.libs/libsnappy.a /usr/local/lib
  fi
}

function install_yara() {
  TARBALL=yara-3.3.0.tar.gz
  URL=$DEPS_URL/yara-3.3.0.tar.gz
  SOURCE=yara-3.3.0

  if provision yara /usr/local/lib/libyara.a; then
    pushd $SOURCE
    ./bootstrap.sh
    CC="$CC" CXX="$CXX" ./configure --with-pic --enable-static
    make -j $THREADS
    sudo make install
    popd
  fi
}

function install_boost() {
  TARBALL=boost_1_55_0.tar.gz
  URL=$DEPS_URL/boost_1_55_0.tar.gz
  SOURCE=boost_1_55_0

  if provision boost /usr/local/lib/libboost_thread.a; then
    pushd $SOURCE
    ./bootstrap.sh
    sudo ./b2 --with=all -j $THREADS toolset="gcc" install || true
    sudo ldconfig
    popd
  fi
}

function install_gflags() {
  TARBALL=v2.1.1.tar.gz
  URL=$DEPS_URL/v2.1.1.tar.gz
  SOURCE=gflags-2.1.1

  if provision gflags /usr/local/lib/libgflags.a; then
    pushd $SOURCE
    cmake -DCMAKE_CXX_FLAGS="$CFLAGS" -DGFLAGS_NAMESPACE:STRING=google .
    CC="$CC" CXX="$CXX" make -j $THREADS
    sudo make install
    popd
  fi
}

function install_iptables_dev() {
  TARBALL=iptables-1.4.21.tar.gz
  URL=$DEPS_URL/iptables-1.4.21.tar.gz
  SOURCE=iptables-1.4.21

  if provision iptables_dev /usr/local/lib/libip4tc.a; then
    pushd $SOURCE
    ./configure --disable-shared --prefix=/usr/local
    pushd libiptc
    CC="$CC" CXX="$CXX" make -j $THREADS
    sudo make install
    popd
    pushd include
    sudo make install
    popd
    popd
  fi
}

function install_libcryptsetup() {
  TARBALL=cryptsetup-1.6.7.tar.gz
  URL=$DEPS_URL/cryptsetup-1.6.7.tar.gz
  SOURCE=cryptsetup-1.6.7

  if provision libcryptsetup /usr/local/lib/libcryptsetup.a; then
    pushd $SOURCE
    ./autogen.sh --prefix=/usr/local --enable-static --disable-kernel_crypto
    ./configure --prefix=/usr/local --enable-static --disable-kernel_crypto
    pushd lib
    make -j $THREADS
    sudo make install
    popd
    popd
  fi
}

function install_autoconf() {
  TARBALL=autoconf-2.69.tar.gz
  URL=$DEPS_URL/autoconf-2.69.tar.gz
  SOURCE=autoconf-2.69

  # Two methods for provisioning autoconf (1) install, (2) upgrade
  PROVISION_AUTOCONF=false
  if provision autoconf /usr/bin/autoconf; then
    PROVISION_AUTOCONF=true
  elif [[ `autoconf -V | head -1 | awk '{print $4}' | sed 's/\.//g'` -lt "269" ]]; then
    provision autoconf
    PROVISION_AUTOCONF=true
  fi

  if $PROVISION_AUTOCONF; then
    pushd $SOURCE
    ./configure --prefix=/usr
    CC="$CC" CXX="$CXX" make -j $THREADS
    sudo make install
    popd
  fi
}

function install_automake() {
  TARBALL=automake-1.14.tar.gz
  URL=$DEPS_URL/automake-1.14.tar.gz
  SOURCE=automake-1.14

  if provision automake /usr/bin/automake; then
    pushd $SOURCE
    ./bootstrap.sh
    ./configure --prefix=/usr
    CC="$CC" CXX="$CXX" make -j $THREADS
    sudo make install
    popd
  fi
}

function install_libtool() {
  TARBALL=libtool-2.4.5.tar.gz
  URL=$DEPS_URL/libtool-2.4.5.tar.gz
  SOURCE=libtool-2.4.5

  if provision libtool /usr/bin/libtool; then
    pushd $SOURCE
    ./configure --prefix=/usr
    make -j $THREADS
    sudo make install
    popd
  fi
}

function install_pkgconfig() {
  TARBALL=pkg-config-0.28.tar.gz
  URL=$DEPS_URL/pkg-config-0.28.tar.gz
  SOURCE=pkg-config-0.28

  if provision pkg-config /usr/bin/pkg-config; then
    pushd $SOURCE
    sudo rm /usr/bin/x86_64-unknown-linux-gnu-pkg-config || true
    ./configure --with-internal-glib --prefix=/usr
    make -j $THREADS
    sudo make install
    popd
  fi
}

function install_udev_devel_095() {
  TARBALL=udev-095.tar.gz
  URL=$DEPS_URL/udev-095.tar.gz
  SOURCE=udev-095

  if provision udev-095 /usr/local/lib/libudev.a; then
    pushd $SOURCE
    CC="$CC" CXX="$CXX" make libudev.a
    sudo cp libudev.a /usr/local/lib/
    popd
  fi
}

function install_pip() {
  PYTHON_EXECUTABLE=$1
  URL=$DEPS_URL/get-pip.py

  if [[ ! -e /usr/bin/pip ]]; then
    curl $URL | sudo $PYTHON_EXECUTABLE -
  fi
}

function install_ruby() {
  TARBALL=ruby-1.8.7-p370.tar.gz
  URL=$DEPS_URL/ruby-1.8.7-p370.tar.gz
  SOURCE=ruby-1.8.7-p370

  if provision ruby-1.8.7 /usr/local/bin/ruby; then
    pushd $SOURCE
    ./configure --prefix=/usr/local
    CC="$CC" CXX="$CXX" make -j $THREADS
    sudo make install
    popd
  fi

  TARBALL=rubygems-1.8.24.tar.gz
  URL=$DEPS_URL/rubygems-1.8.24.tar.gz
  SOURCE=rubygems-1.8.24

  if provision rubygems-1.8.24 /usr/local/bin/gem; then
    pushd $SOURCE
    sudo ruby setup.rb
    popd
  fi
}

function install_libaptpkg() {
  TARBALL=apt-0.8.16-12.10.22.tar.gz
  URL=$DEPS_URL/apt-0.8.16-12.10.22.tar.gz
  SOURCE=apt-0.8.16-12.10.22
  if provision libaptpkg /usr/local/lib/libapt-pkg.a; then
    pushd $SOURCE
    mkdir build
    pushd build
    ../configure --prefix=/usr/local
    make -j $THREADS
    sudo make install
    popd
    popd
  fi
}

function package() {
  if [[ $FAMILY = "debian" ]]; then
    if [[ -n "$(dpkg --get-selections | grep $1)" ]]; then
      log "$1 is already installed. skipping."
    else
      log "installing $1"
      sudo DEBIAN_FRONTEND=noninteractive apt-get install $1 -y
    fi
  elif [[ $FAMILY = "redhat" ]]; then
    if [[ ! -n "$(rpm -V $1)" ]]; then
      log "$1 is already installed. skipping."
    else
      log "installing $1"
      sudo yum install $1 -y
    fi
  elif [[ $OS = "darwin" ]]; then
    if [[ -n "$(brew list | grep $1)" ]]; then
      log "$1 is already installed. skipping."
    else
      log "installing $1"
      brew install --build-bottle --build-from-source $1 || brew upgrade --build-from-source $@
    fi
  elif [[ $OS = "freebsd" ]]; then
    if pkg info -q $1; then
      log "$1 is already installed. skipping."
    else
      log "installing $1"
      sudo pkg install -y $1
    fi
  fi
}

function remove_package() {
  if [[ $FAMILY = "debian" ]]; then
    if [[ -n "$(dpkg --get-selections | grep $1)" ]]; then
      log "removing $1"
      sudo apt-get remove $1 -y
    else
      log "Removing: $1 is not installed. skipping."
    fi
  elif [[ $FAMILY = "redhat" ]]; then
    if [[ -n "$(rpm -qa | grep $1)" ]]; then
      log "removing $1"
      sudo yum remove $1 -y
    else
      log "Removing: $1 is not installed. skipping."
    fi
  elif [[ $OS = "darwin" ]]; then
    if [[ -n "$(brew list | grep $1)" ]]; then
      log "removing $1"
      brew uninstall $1
    else
      log "Removing: $1 is not installed. skipping."
    fi
  elif [[ $OS = "freebsd" ]]; then
    if ! pkg info -q $1; then
      log "removing $1"
      sudo pkg delete -y $1
    else
      log "Removing: $1 is not installed. skipping."
    fi
  fi
}

function gem_install() {
  if [[ -n "$(gem list | grep $1)" ]]; then
    log "$1 is already installed. skipping."
  else
    sudo gem install $1
  fi
}

function provision() {
  local _name=$1
  local _install_check=$2

  if [[ ! -f $_install_check ]]; then
    log "$_name is not installed/provisioned. installing..."
    if [[ ! -f $TARBALL ]]; then
      log "$_name has not been downloaded. downloading..."
      wget "$URL"
    else
      log "$_name is already downloaded. skipping download."
    fi
    if [[ ! -d $SOURCE ]]; then
      log "$_name has not been extracted. extracting..."
      tar -xzf $TARBALL
    fi
    return 0
  fi
  log "$_name is already installed. skipping provision."
  return 1
}

function check() {
  platform OS

  if [[ $OS = "darwin" ]]; then
    HASH=`shasum $0 | awk '{print $1}'`
  elif [[ $OS = "freebsd" ]]; then
    HASH=`sha1 -q $0`
  else
    HASH=`sha1sum $0 | awk '{print $1}'`
  fi

  if [[ "$1" = "build" ]]; then
    echo $HASH > "$2/.provision"
    if [[ ! -z "$SUDO_USER" ]]; then
      chown $SUDO_USER "$2/.provision" > /dev/null 2>&1 || true
    fi
    return
  elif [[ ! "$1" = "check" ]]; then
    return
  fi

  if [[ "$#" < 2 ]]; then
    echo "Usage: $0 (check|build) BUILD_PATH"
    exit 1
  fi

  CHECKPOINT=`cat $2/.provision 2>&1 &`
  if [[ ! $HASH = $CHECKPOINT ]]; then
    echo "Requested dependencies may have changed, run: make deps"
    exit 1
  fi
  exit 0
}
