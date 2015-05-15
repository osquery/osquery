#!/usr/bin/env bash

#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function main_ubuntu() {
  if [[ $DISTRO = "precise" ]]; then
    sudo add-apt-repository -y ppa:ubuntu-toolchain-r/test
  fi

  sudo apt-get update -y

  package wget
  package git
  package unzip
  package build-essential
  package autopoint
  package bison
  package flex
  package devscripts
  package debhelper
  package python-pip
  package python-dev
  package linux-headers-generic
  package ruby-dev
  package gcc
  package doxygen

  package libssl-dev
  package liblzma-dev
  package uuid-dev
  package libpopt-dev
  package libdpkg-dev
  package libapt-pkg-dev
  package libudev-dev
  package libblkid-dev

  package libsnappy-dev
  package libbz2-dev
  package libreadline-dev

  if [[ $DISTRO = "precise" ]]; then
    # Need gcc 4.8 from ubuntu-toolchain-r/test to compile RocksDB/osquery.
    package gcc-4.8
    package g++-4.8
    sudo update-alternatives \
      --install /usr/bin/gcc gcc /usr/bin/gcc-4.8 150 \
      --slave /usr/bin/g++ g++ /usr/bin/g++-4.8

    package clang-3.4
    package clang-format-3.4
    package rubygems

    # Temporary removes (so we can override default paths).
    remove_package pkg-config
    remove_package autoconf
    remove_package automake
    remove_package libtool

    install_pkgconfig
    install_autoconf
    install_automake
    install_libtool
    install_boost
  else
    package clang-3.5
    package clang-format-3.5

    sudo ln -sf /usr/bin/clang-3.5 /usr/bin/clang
    sudo ln -sf /usr/bin/clang++-3.5 /usr/bin/clang++
    sudo ln -sf /usr/bin/clang-format-3.5 /usr/bin/clang-format
    sudo ln -sf /usr/bin/llvm-config-3.5 /usr/bin/llvm-config

    package pkg-config
    package autoconf
    package automake
    package libtool
    package libboost1.55-all-dev
  fi

  set_cc gcc #-4.8
  set_cxx g++ #-4.8

  install_cmake
  install_gflags
  install_iptables_dev

  set_cc clang
  set_cxx clang++

  install_thrift
  install_rocksdb
  install_yara

  # Need headers and PC macros
  package libgcrypt-dev
  package libdevmapper-dev

  install_libcryptsetup

  gem_install fpm
}
