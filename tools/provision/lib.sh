#!/usr/bin/env bash

#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function install_cmake() {
  if [[ ! -f /usr/local/bin/cmake ]]; then
    if [[ ! -f cmake-3.2.1.tar.gz ]]; then
      log "downloading the cmake source"
      wget https://osquery-packages.s3.amazonaws.com/deps/cmake-3.2.1.tar.gz
    fi
    if [[ ! -d cmake-3.2.1 ]]; then
      log "unpacking the cmake source"
      tar -xf cmake-3.2.1.tar.gz
    fi
    log "building cmake"

    pushd cmake-3.2.1
    ./bootstrap --prefix=/usr/local/
    make
    sudo make install
    popd
  else
    log "cmake is already installed. skipping."
  fi
}

function install_thrift() {
  if [[ ! -f /usr/local/lib/libthrift.a ]]; then
    if [[ ! -f 0.9.1.tar.gz ]]; then
      wget https://osquery-packages.s3.amazonaws.com/deps/0.9.1.tar.gz
    fi
    if [[ ! -d thrift-0.9.1 ]]; then
      tar -xf 0.9.1.tar.gz
    fi
    pushd thrift-0.9.1
    ./bootstrap.sh
    ./configure CFLAGS="$CFLAGS" \
      --with-cpp=yes \
      --with-python=yes \
      --with-ruby=no \
      --with-go=no \
      --with-erlang=no \
      --with-java=no \
      --with-php=no
    make
    sudo make install
    popd
  else
    log "thrift is installed. skipping."
  fi
}

function install_rocksdb() {
  if [[ ! -f /usr/local/lib/librocksdb.a ]]; then
    if [[ ! -f rocksdb-3.10.2.tar.gz ]]; then
      wget https://osquery-packages.s3.amazonaws.com/deps/rocksdb-3.10.2.tar.gz
    else
      log "rocksdb source is already downloaded. skipping."
    fi
    if [[ ! -d rocksdb-rocksdb-3.10.2 ]]; then
      tar -xf rocksdb-3.10.2.tar.gz
    fi
    if [[ ! -f rocksdb-rocksdb-3.10.2/librocksdb.a ]]; then
      if [[ $OS = "ubuntu" ]]; then
        CLANG_INCLUDE="-I/usr/include/clang/3.4/include"
      elif [ $OS = "centos" ] || [ $OS = "rhel" ]; then
        CLANG_VERSION=`clang --version | grep version | cut -d" " -f3`
        CLANG_INCLUDE="-I/usr/lib/clang/$CLANG_VERSION/include"
      fi
      pushd rocksdb-rocksdb-3.10.2
      make static_lib CFLAGS="$CLANG_INCLUDE $CFLAGS"
      popd
    fi
    sudo cp rocksdb-rocksdb-3.10.2/librocksdb.a /usr/local/lib
    sudo cp -R rocksdb-rocksdb-3.10.2/include/rocksdb /usr/local/include
  else
    log "rocksdb already installed. skipping."
  fi
}

function install_snappy() {
  if [[ ! -f /usr/local/lib/libsnappy.a ]]; then
    if [[ ! -f snappy-1.1.1.tar.gz ]]; then
      wget https://osquery-packages.s3.amazonaws.com/deps/snappy-1.1.1.tar.gz
    else
      log "snappy source is already downloaded. skipping."
    fi
    if [[ ! -d snappy-1.1.1 ]]; then
      tar -xf snappy-1.1.1.tar.gz
    fi
    if [[ ! -f snappy-1.1.1/.libs/libsnappy.a ]]; then
      pushd snappy-1.1.1
      ./configure --with-pic --enable-static
      make
      popd
    fi
    sudo cp snappy-1.1.1/.libs/libsnappy.a /usr/local/lib
  else
    log "snappy library is already installed. skipping."
  fi
}

function install_yara() {
  if [[ ! -f /usr/local/lib/libyara.a ]]; then
    if [[ ! -f yara-3.3.0.tar.gz ]]; then
      wget https://s3.amazonaws.com/osquery-packages/deps/yara-3.3.0.tar.gz
    else
      log "yara source is already downloaded. skipping."
    fi
    if [[ ! -d yara-3.3.0 ]]; then
      tar xzf yara-3.3.0.tar.gz
    fi
    pushd yara-3.3.0
    ./bootstrap.sh
    CC="$CC" CXX="$CXX" ./configure --with-pic --enable-static
    make
    sudo make install
    popd
  else
    log "yara library is already installed. skipping."
  fi
}

function install_boost() {
  if [[ ! -f /usr/local/lib/libboost_thread.a ]]; then
    if [[ ! -f boost_1_55_0.tar.gz ]]; then
      wget https://osquery-packages.s3.amazonaws.com/deps/boost_1_55_0.tar.gz
    else
      log "boost source is already downloaded. skipping."
    fi
    if [[ ! -d boost_1_55_0 ]]; then
      tar -xf boost_1_55_0.tar.gz
    fi
    pushd boost_1_55_0
    ./bootstrap.sh
    n=`getconf _NPROCESSORS_ONLN`
    sudo ./b2 --with=all -j $n toolset="$CC" install
    sudo ldconfig
    popd
  else
    log "boost library is already installed. skipping."
  fi
}

function install_gflags() {
  if [[ ! -f /usr/local/lib/libgflags.a ]]; then
    if [[ ! -f v2.1.1.tar.gz ]]; then
      wget https://osquery-packages.s3.amazonaws.com/deps/v2.1.1.tar.gz
    else
      log "gflags source is already downloaded. skipping."
    fi
    if [[ ! -d gflags-2.1.1 ]]; then
      tar -xf v2.1.1.tar.gz
    fi
    if [[ ! -x "$(which gmake)" ]]; then
      sudo ln -s `which make` /usr/local/bin/gmake
    fi
    pushd gflags-2.1.1
    cmake -DCMAKE_CXX_FLAGS="$CFLAGS" -DGFLAGS_NAMESPACE:STRING=google .
    make
    sudo make install
    popd
  else
    log "gflags library is already installed. skipping."
  fi
}

function install_autoconf() {
  if [[ ! -f /usr/bin/autoconf ]] || [[ `autoconf -V | head -1 | awk '{print $4}' | sed 's/\.//g'` -lt "269" ]]; then
    if [[ ! -f autoconf-2.69.tar.gz ]]; then
      wget https://osquery-packages.s3.amazonaws.com/deps/autoconf-2.69.tar.gz
    else
      log "autoconf is already downloaded. skipping."
    fi
    if [[ ! -d autoconf-2.69 ]]; then
      tar -xf autoconf-2.69.tar.gz
    fi
    pushd autoconf-2.69
    ./configure --prefix=/usr
    make
    sudo make install
    popd
  else
    log "autoconf is already installed. skipping."
  fi
}

function install_automake() {
  if [[ ! -f /usr/bin/automake ]]; then
    if [[ ! -f automake-1.14.tar.gz ]]; then
      wget https://osquery-packages.s3.amazonaws.com/deps/automake-1.14.tar.gz
    else
      log "automake is already downloaded. skipping."
    fi
    if [[ ! -d automake-1.14 ]]; then
      tar -xf automake-1.14.tar.gz
    fi
    pushd automake-1.14
    ./configure --prefix=/usr
    make
    sudo make install
    popd
  else
    log "automake is already installed. skipping."
  fi
}

function install_libtool() {
  if [[ ! -f /usr/bin/libtool ]]; then
    if [[ ! -f libtool-2.4.5.tar.gz ]]; then
      wget https://osquery-packages.s3.amazonaws.com/deps/libtool-2.4.5.tar.gz
    else
      log "libtool is already downloaded. skipping."
    fi
    if [[ ! -d libtool-2.4.5 ]]; then
      tar -xf libtool-2.4.5.tar.gz
    fi
    pushd libtool-2.4.5
    ./configure --prefix=/usr
    make
    sudo make install
    popd
  else
    log "libtool is already installed. skipping."
  fi
}

function package() {
  if [[ $OS = "ubuntu" ]]; then
    if [[ -n "$(dpkg --get-selections | grep $1)" ]]; then
      log "$1 is already installed. skipping."
    else
      log "installing $1"
      sudo apt-get install $1 -y
    fi
  elif [ $OS = "centos" ] || [ $OS = "rhel" ]; then
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
      brew install --build-bottle $1 || brew upgrade $@
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
  if [[ $OS = "ubuntu" ]]; then
    if [[ -n "$(dpkg --get-selections | grep $1)" ]]; then
      log "removing $1"
      sudo apt-get remove $1 -y
    else
      log "Removing: $1 is not installed. skipping."
    fi
  elif [ $OS = "centos" ] || [ $OS = "rhel" ]; then
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
    if [[ -n "$(pkg info -q $1)" ]]; then
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
