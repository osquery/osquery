#!/bin/bash

set -e

WORKING_DIR="/var/osquery/sources/"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export PATH="$PATH:/usr/local/bin"

function platform() {
  local  __resultvar=$1
  if [[ -f "/etc/yum.conf" ]]; then
    eval $__resultvar="centos"
  elif [[ -f "/etc/dpkg/dpkg.cfg" ]]; then
    eval $__resultvar="ubuntu"
  elif [[ -f "/etc/pf.conf" ]]; then
    eval $__resultvar="darwin"
  fi
}

function log() {
  echo "[+] $1"
}

function fatal() {
  echo "[!] $1"
  exit 1
}

function set_cxx() {
  export CXX=$1
  export CMAKE_CXX_COMPILER=$1
}

function add_cxx_flag() {
  export CXXFLAGS="$CXXFLAGS $1"
  export CMAKE_CXX_FLAGS="$CMAKE_CXX_FLAGS $1"
}

function set_cc() {
  export CC=$1
  export CMAKE_C_COMPILER=$1
}

# cmake
# downloads: http://www.cmake.org/download/

function install_cmake() {
  if [ $OS = "centos" ] || [ $OS = "ubuntu" ] || [ $OS = "darwin" ]; then
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
      make install
      popd
    fi
  fi
}

function install_thrift() {
  if [[ ! -f 0.9.1.tar.gz ]]; then
    wget https://github.com/apache/thrift/archive/0.9.1.tar.gz
  fi
  if [[ ! -d thrift-0.9.1 ]]; then
    tar -xf 0.9.1.tar.gz
  fi
  if [[ ! -f /usr/local/lib/libthrift.so ]]; then
    pushd thrift-0.9.1
    ./bootstrap.sh
    ./configure
    make
    make install
    popd
  else
    log "thrift is installed. skipping."
  fi
}

function install_rocksdb() {
  if [[ ! -f rocksdb-3.5.tar.gz ]]; then
    wget https://github.com/facebook/rocksdb/archive/rocksdb-3.5.tar.gz
  fi
  if [[ ! -d rocksdb-rocksdb-3.5 ]]; then
    tar -xf rocksdb-3.5.tar.gz
  fi
  if [[ ! -f rocksdb-rocksdb-3.5/librocksdb.so ]]; then
    pushd rocksdb-rocksdb-3.5
    make shared_lib
    popd
  fi
  if [[ ! -f /usr/local/lib/librocksdb.so ]]; then
    cp rocksdb-rocksdb-3.5/librocksdb.so /usr/local/lib
    cp -R rocksdb-rocksdb-3.5/include/rocksdb /usr/local/include
  else
    log "rocksdb already installed. skipping."
  fi
}

function install_gtest() {
  if [[ ! -f gtest-1.7.0.zip ]]; then
    wget https://googletest.googlecode.com/files/gtest-1.7.0.zip
  fi
  if [[ ! -d gtest-1.7.0 ]]; then
    unzip gtest-1.7.0.zip
  fi
  if [[ ! -f gtest-1.7.0/lib/libgtest.la ]]; then
    pushd gtest-1.7.0
    ./configure
    make
    make install
    popd
  fi
  if [[ ! -f /usr/local/lib/libgtest.la ]]; then
    cp -R gtest-1.7.0/include/gtest /usr/local/include
  else
    log "gtest is already installed. skipping"
  fi
}

function install_sqlite3() {
  if [[ ! -f sqlite3-3.8.4.3.tar.gz ]]; then
    wget https://github.com/osquery/sqlite3/archive/sqlite3-3.8.4.3.tar.gz
  fi
  if [[ ! -d sqlite3-sqlite3-3.8.4.3 ]]; then
    tar -xf sqlite3-sqlite3-3.8.4.3.tar.gz
  fi
  if [[ ! -f sqlite3-sqlite3-3.8.4.3/build/libosquery_sqlite3.a ]]; then
    pushd sqlite3-sqlite3-3.8.4.3
    mkdir -p build
    pushd build
    cmake ..
    make
    make install
    popd
    popd
  else
    log "sqlite3 is already built. skipping."
  fi

}

function package() {
  if [[ $OS = "ubuntu" ]]; then
    if dpkg --get-selections | grep --quiet $1; then
      log "$1 is already installed. skipping."
    else
      apt-get install $@ -y
    fi
  elif [[ $OS = "centos" ]]; then
    if rpm -qa | grep --quiet $1; then
      log "$1 is already installed. skipping."
    else
      yum install $@ -y
    fi
  elif [[ $OS = "darwin" ]]; then
    if brew list | grep --quiet $1; then
      log "$1 is already installed. skipping."
    else
      brew install $@ || brew upgrade $@
    fi
  fi
}

function main() {
  platform OS

  mkdir -p $WORKING_DIR
  cd $WORKING_DIR

  if [[ $EUID -ne 0 ]]; then
    fatal "this script must be run as root. exiting."
  fi

  if [[ $OS = "centos" ]]; then
    log "detected centos"
  elif [[ $OS = "ubuntu" ]]; then
    log "detected ubuntu"
  elif [[ $OS = "darwin" ]]; then
    log "detected mac os x"

    if [[ ! -f "/usr/local/bin/brew" ]]; then
      fatal "could not find homebrew. please install it from http://brew.sh/"
    fi

    if brew list | grep --quiet wget; then
      log "wget is already installed. skipping"
    else
      brew install wget
    fi
  else
    fatal "could not detect the current operating system. exiting."
  fi

  if [ $OS = "centos" ] || [ $OS = "ubuntu" ]; then
    THREADS=`cat /proc/cpuinfo | grep processor | wc -l`
  elif [[ $OS = "darwin" ]]; then
    THREADS=`sysctl hw.ncpu | awk '{print $2}'`
  fi

  if [[ $OS = "ubuntu" ]]; then
    apt-get update

    package git
    package unzip
    package build-essential
    package cmake

    package python-pip
    package python-dev

    package clang-3.4
    package clang-format-3.4

    set_cc clang
    set_cxx clang++

    package libboost1.55-all-dev
    package libgflags-dev
    package libgoogle-glog-dev
    package libsnappy-dev
    package libbz2-dev
    package libreadline-dev
    package libprocps3-dev

    package libtool
    package autoconf
    package automake
    package pkg-config
    package libssl-dev
    package bison
    package flex
    install_thrift

    install_rocksdb

    install_gtest

    install_sqlite3
  elif [[ $OS = "centos" ]]; then
    yum update -y

    package git-all
    package unzip
    package xz

  elif [[ $OS = "darwin" ]]; then
    package cmake
    package boost --c++11
    package gflags
    package glog
    package snappy
    package readline
    package thrift
  fi

  if [ $OS = "ubuntu" ] || [ $OS = "centos" ]; then
    pip install -r /vagrant/requirements.txt
  elif [[ $OS = "darwin" ]]; then
    pip install -r $SCRIPT_DIR/../requirements.txt
  fi
}

main
