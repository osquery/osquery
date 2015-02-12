#!/usr/bin/env bash

#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR="$SCRIPT_DIR/../build"
WORKING_DIR="$SCRIPT_DIR/../.sources"
export PATH="$PATH:/usr/local/bin"

source "$SCRIPT_DIR/lib.sh"

# cmake
# downloads: http://www.cmake.org/download/

function install_cmake() {
  if [ "$OS" = "centos" ] || [ "$OS" = "ubuntu" ] || [ "$OS" = "darwin" ]; then
    if [[ -f /usr/local/bin/cmake ]]; then
      log "cmake is already installed. skipping."
    else
      if [[ ! -f cmake-2.8.12.2.tar.gz ]]; then
        log "downloading the cmake source"
        wget http://www.cmake.org/files/v2.8/cmake-2.8.12.2.tar.gz
      fi
      if [[ ! -d cmake-2.8.12.2 ]]; then
        log "unpacking the cmake source"
        tar -xf cmake-2.8.12.2.tar.gz
      fi
      if [[ -f /usr/local/bin/cmake ]]; then
        log "cmake is already installed. skipping."
      else
        log "building cmake"
        pushd cmake-2.8.12.2 > /dev/null
        CC=clang CXX=clang++ ./configure
        make
        sudo make install
        popd
      fi
    fi
  fi
}

function install_thrift() {
  if [[ ! -f /usr/local/lib/libthrift.a ]]; then
    if [[ ! -f 0.9.1.tar.gz ]]; then
      wget https://github.com/apache/thrift/archive/0.9.1.tar.gz
    fi
    if [[ ! -d thrift-0.9.1 ]]; then
      tar -xf 0.9.1.tar.gz
    fi
    pushd thrift-0.9.1
    ./bootstrap.sh
    ./configure --with-cpp=yes --with-ruby=no --with-go=no --with-erlang=no --with-java=no --with-python=no
    make
    sudo make install
    popd
  else
    log "thrift is installed. skipping."
  fi
}

function install_rocksdb() {
  if [[ ! -f /usr/local/lib/librocksdb.a ]]; then
    if [[ ! -f rocksdb-3.5.tar.gz ]]; then
      wget https://github.com/facebook/rocksdb/archive/rocksdb-3.5.tar.gz
    fi
    if [[ ! -d rocksdb-rocksdb-3.5 ]]; then
      tar -xf rocksdb-3.5.tar.gz
    fi
    if [ "$OS" = "ubuntu" ] || [ "$OS" = "centos" ]; then
      if [[ ! -f rocksdb-rocksdb-3.5/librocksdb.a ]]; then
        if [[ $OS = "ubuntu" ]]; then
          CLANG_INCLUDE="-I/usr/include/clang/3.4/include"
        elif [[ $OS = "centos" ]]; then
          CLANG_VERSION=`clang --version | grep version | cut -d" " -f3`
          CLANG_INCLUDE="-I/usr/lib/clang/$CLANG_VERSION/include"
        fi
        pushd rocksdb-rocksdb-3.5
        make static_lib CFLAGS="$CLANG_INCLUDE"
	      popd
      fi
      sudo cp rocksdb-rocksdb-3.5/librocksdb.a /usr/local/lib
      sudo cp -R rocksdb-rocksdb-3.5/include/rocksdb /usr/local/include
    elif [[ $OS = "darwin" ]]; then
      if [[ ! -f rocksdb-rocksdb-3.5/librocksdb.a ]]; then
        pushd rocksdb-rocksdb-3.5
        make static_lib
        popd
      fi
      sudo cp rocksdb-rocksdb-3.5/librocksdb.a /usr/local/lib
      sudo cp -R rocksdb-rocksdb-3.5/include/rocksdb /usr/local/include
    fi
  else
    log "rocksdb already installed. skipping."
  fi
}

function install_boost() {
  if [[ ! -f /usr/local/lib/libboost_thread.a ]]; then
    if [[ ! -f boost_1_55_0.tar.gz ]]; then
      wget -O boost_1_55_0.tar.gz http://sourceforge.net/projects/boost/files/boost/1.55.0/boost_1_55_0.tar.gz/download
    else
      log "boost source is already downloaded. skipping."
    fi
    if [[ ! -d boost_1_55_0 ]]; then
      tar -xf boost_1_55_0.tar.gz
    fi
    pushd boost_1_55_0
    ./bootstrap.sh
    n=`getconf _NPROCESSORS_ONLN`
    sudo ./b2 --with=all -j $n toolset=clang install
    sudo ldconfig
    popd
  else
    log "boost library is already installed. skipping."
  fi
}

function install_gflags() {
  if [[ ! -f /usr/local/lib/libgflags.a ]]; then
    if [[ ! -f v2.1.1.tar.gz ]]; then
      wget https://github.com/schuhschuh/gflags/archive/v2.1.1.tar.gz
    else
      log "gflags source is already downloaded. skipping."
    fi
    if [[ ! -d gflags-2.1.1 ]]; then
      tar -xf v2.1.1.tar.gz
    fi
    pushd gflags-2.1.1
    cmake -DCMAKE_CXX_FLAGS=-fPIC -DGFLAGS_NAMESPACE:STRING=google .
    make
    sudo make install
    popd
  else
    log "gflags library is already installed. skipping."
  fi
}

function install_autoconf() {
  if [[ ! -f /usr/bin/autoconf ]]; then
    if [[ ! -f autoconf-2.69.tar.gz ]]; then
      wget http://ftp.gnu.org/gnu/autoconf/autoconf-2.69.tar.gz
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
      wget http://ftp.gnu.org/gnu/automake/automake-1.14.tar.gz
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
      wget http://ftpmirror.gnu.org/libtool/libtool-2.4.5.tar.gz
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
    if dpkg --get-selections | grep --quiet $1; then
      log "$1 is already installed. skipping."
    else
      sudo apt-get install $@ -y
    fi
  elif [[ $OS = "centos" ]]; then
    if rpm -qa | grep --quiet $1; then
      log "$1 is already installed. skipping."
    else
      sudo yum install $@ -y
    fi
  elif [[ $OS = "darwin" ]]; then
    if brew list | grep --quiet $1; then
      log "$1 is already installed. skipping."
    else
      brew install --build-bottle $@ || brew upgrade $@
    fi
  elif [[ $OS = "freebsd" ]]; then
    if pkg info -q $1; then
      log "$1 is already installed. skipping."
    else
      sudo pkg install -y $@
    fi
  fi
}

function remove_package() {
  if [[ $OS = "ubuntu" ]]; then
    if dpkg --get-selections | grep --quiet $1; then
      sudo apt-get remove $@ -y
    else
      log "Removing: $1 is not installed. skipping."
    fi
  elif [[ $OS = "centos" ]]; then
    if rpm -qa | grep --quiet $1; then
      sudo yum remove $@ -y
    else
      log "Removing: $1 is not installed. skipping."
    fi
  elif [[ $OS = "darwin" ]]; then
    if brew list | grep --quiet $1; then
      brew uninstall $@
    else
      log "Removing: $1 is not installed. skipping."
    fi
  elif [[ $OS = "freebsd" ]]; then
    if pkg info -q $1; then
      sudo pkg delete -y $@
    else
      log "Removing: $1 is not installed. skipping."
    fi
  fi
}

function gem_install() {
  if gem list | grep --quiet $1; then
    log "$1 is already installed. skipping."
  else
    sudo gem install $@
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

function main() {
  platform OS
  distro $OS DISTRO

  if [[ $1 = "get_platform" ]]; then
    echo "$OS;$DISTRO"
    return 0
  fi

  mkdir -p "$WORKING_DIR"
  if [[ ! -z "$SUDO_USER" ]]; then
    echo "chown -h $SUDO_USER $BUILD_DIR/*"
    chown -h $SUDO_USER:$SUDO_GID "$BUILD_DIR" || true
    if [[ $OS = "linux" ]]; then
      chown -h $SUDO_USER:$SUDO_GID "$BUILD_DIR/linux" || true
    fi
    chown $SUDO_USER:$SUDO_GID "$WORKING_DIR" > /dev/null 2>&1 || true
  fi
  cd "$WORKING_DIR"

  if [[ $OS = "centos" ]]; then
    log "detected centos ($DISTRO)"
  elif [[ $OS = "ubuntu" ]]; then
    log "detected ubuntu ($DISTRO)"
  elif [[ $OS = "darwin" ]]; then
    log "detected mac os x ($DISTRO)"
  elif [[ $OS = "freebsd" ]]; then
    log "detected freebsd ($DISTRO)"
  else
    fatal "could not detect the current operating system. exiting."
  fi

  threads THREADS

  if [[ $OS = "ubuntu" ]]; then

    if [[ $DISTRO = "precise" ]]; then
      sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
    fi
    sudo rm -Rf /var/lib/apt/lists/*
    sudo apt-get update
    sudo apt-get clean

    package git
    package unzip
    package build-essential
    package libtool
    package autoconf
    package automake
    package pkg-config
    package libssl-dev
    package liblzma-dev
    package bison
    package flex
    package python-pip
    package python-dev
    package libbz2-dev
    package devscripts
    package debhelper
    package clang-3.4
    package clang-format-3.4
    package librpm-dev
    package libdpkg-dev
    package libapt-pkg-dev
    package libudev-dev
    package libblkid-dev
    package linux-headers-generic
    package ruby-dev
    package gcc
    package doxygen

    set_cc clang
    set_cxx clang++

    if [[ $DISTRO = "precise" ]]; then
      package rubygems
      package gcc-4.7
      package g++-4.7
      sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.7 100 --slave /usr/bin/g++ g++ /usr/bin/g++-4.7
      install_boost
      install_cmake
    else
      package cmake
      package libboost1.55-all-dev
    fi

    install_gflags

    if [[ $DISTRO = "precise" ]]; then
      remove_package libunwind7-dev
    else
      remove_package libunwind8-dev
    fi

    package libsnappy-dev
    package libbz2-dev
    package libreadline-dev

    if [[ $DISTRO = "precise" ]]; then
      package libproc-dev
    else
      package libprocps3-dev
    fi
    install_thrift
    install_rocksdb

    gem_install fpm

  elif [[ $OS = "centos" ]]; then
    sudo yum update -y

    if [[ -z $(rpm -qa | grep 'kernel-headers-3.10') ]]; then
      if [[ $DISTRO = "centos6" ]]; then
        sudo rpm -iv ftp://rpmfind.net/linux/centos/7.0.1406/updates/x86_64/Packages/kernel-headers-3.10.0-123.9.3.el7.x86_64.rpm
      elif [[ $DISTRO = "centos7" ]]; then
        package kernel-headers
      fi
    fi

    package texinfo
    package git-all
    package unzip
    package xz
    package xz-devel
    package epel-release.noarch
    package python-pip.noarch
    package python-devel
    package rpm-build
    package ruby-devel
    package rubygems

    if [[ $DISTRO = "centos6" ]]; then
      pushd /etc/yum.repos.d
      if [[ ! -f /etc/yum.repos.d/devtools-2.repo ]]; then
        sudo wget http://people.centos.org/tru/devtools-2/devtools-2.repo
      fi

      package devtoolset-2-gcc
      package devtoolset-2-binutils
      package devtoolset-2-gcc-c++

      if [[ ! -e /usr/bin/gcc ]]; then
        sudo ln -s /opt/rh/devtoolset-2/root/usr/bin/gcc /usr/bin/gcc
      fi
      if [[ ! -e /usr/bin/g++ ]]; then
        sudo ln -s /opt/rh/devtoolset-2/root/usr/bin/gcc /usr/bin/g++
      fi

      source /opt/rh/devtoolset-2/enable
      if [[ ! -d /usr/lib/gcc ]]; then
        sudo ln -s /opt/rh/devtoolset-2/root/usr/lib/gcc /usr/lib/
      fi
      popd

      package cmake28
    elif [[ $DISTRO = "centos7" ]]; then
      package gcc
      package binutils
      #package gcc-c++
      package cmake
    fi

    if [[ ! -f /usr/bin/cmake ]]; then
      sudo ln -s /usr/bin/cmake28 /usr/bin/cmake
    fi
    if [[ ! -f /usr/bin/ccmake ]]; then
      sudo ln -s /usr/bin/ccmake28 /usr/bin/ccmake
    fi

    package clang
    package clang-devel

    set_cc clang
    set_cxx clang++

    package bzip2
    package bzip2-devel
    package openssl-devel
    package readline-devel
    package procps-devel
    package rpm-devel
    package libblkid-devel

    if [[ $DISTRO = "centos6" ]]; then
      install_boost
    elif [[ $DISTRO = "centos7" ]]; then
      package boost
    fi

    install_gflags
    package doxygen
    package snappy
    package snappy-devel
    package byacc
    package flex
    package bison
    package libudev-devel

    remove_package libunwind-devel

    if [[ $DISTRO = "centos6" ]]; then
      install_autoconf
      install_automake
      install_libtool
      install_thrift
    elif [[ $DISTRO = "centos7" ]]; then
      package autoconf
      package automake
      package libtool
      package thrift
      package thrift-devel
    fi

    install_rocksdb

    gem_install fpm

  elif [[ $OS = "darwin" ]]; then
    type brew >/dev/null 2>&1 || {
      fatal "could not find homebrew. please install it from http://brew.sh/";
    }

    type pip >/dev/null 2>&1 || {
      fatal "could not find pip. please install it using 'sudo easy_install pip'";
    }

    brew update

    package rocksdb
    package cmake
    package makedepend
    package boost
    package gflags
    package thrift

  elif [[ $OS = "freebsd" ]]; then
    package cmake
    package git
    package python
    package py27-pip
    package rocksdb
    package thrift-cpp
  fi

  cd "$SCRIPT_DIR/../"

  if [ $OS = "darwin" ] && [ $DISTRO = "10.8" ]; then
    export CPPFLAGS=-Qunused-arguments
    export CFLAGS=-Qunused-arguments
    sudo -E pip install -r requirements.txt
  else
    sudo pip install -r requirements.txt
  fi
  git submodule init
  git submodule update

  # Remove any previously-cached variables
  rm build/$OS/CMakeCache.txt >/dev/null 2>&1 || true
}

check $1 $2
main $1
