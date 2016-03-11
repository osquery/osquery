#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function add_repo() {
  REPO=$1
  echo "Adding repository: $REPO"
  if [[ $DISTRO = "lucid" ]]; then
    package python-software-properties
    sudo add-apt-repository $REPO
  else
    sudo add-apt-repository -y $REPO
  fi
}

function main_ubuntu() {
  if [[ $DISTRO = "precise" ]]; then
    add_repo ppa:ubuntu-toolchain-r/test
  elif [[ $DISTRO = "lucid" ]]; then
    add_repo ppa:lucid-bleed/ppa
  fi

  sudo apt-get update -y

  if [[ $DISTRO = "lucid" ]]; then
    package git-core
  else
    package git
  fi

  package wget
  package unzip
  package build-essential
  package flex
  package devscripts
  package debhelper
  package python-pip
  package python-dev
  # package linux-headers-generic
  package ruby-dev
  package gcc
  package doxygen

  package autopoint
  package libssl-dev
  package liblzma-dev
  package uuid-dev
  package libpopt-dev
  package libdpkg-dev
  package libudev-dev
  package libblkid-dev

  package libbz2-dev
  package libreadline-dev
  package libcurl4-openssl-dev

  if [[ $DISTRO = "lucid" ]]; then
    package libopenssl-ruby

    package clang
    package g++-multilib
    install_gcc
  elif [[ $DISTRO = "precise" ]]; then
    # Need gcc 4.8 from ubuntu-toolchain-r/test to compile RocksDB/osquery.
    package gcc-4.8
    package g++-4.8
    sudo update-alternatives \
      --install /usr/bin/gcc gcc /usr/bin/gcc-4.8 150 \
      --slave /usr/bin/g++ g++ /usr/bin/g++-4.8

    package clang-3.4
    package clang-format-3.4
  fi

  if [[ $DISTRO = "precise" || $DISTRO = "lucid" ]]; then
    package rubygems

    # Temporary removes (so we can override default paths).
    package autotools-dev

    #remove_package pkg-config
    remove_package autoconf
    remove_package automake
    remove_package libtool

    #install_pkgconfig
    package pkg-config

    install_autoconf
    install_automake
    install_libtool
  else
    package clang-3.6
    package clang-format-3.6

    sudo ln -sf /usr/bin/clang-3.6 /usr/bin/clang
    sudo ln -sf /usr/bin/clang++-3.6 /usr/bin/clang++
    sudo ln -sf /usr/bin/clang-format-3.6 /usr/bin/clang-format
    sudo ln -sf /usr/bin/llvm-config-3.6 /usr/bin/llvm-config
    sudo ln -sf /usr/bin/llvm-symbolizer-3.6 /usr/bin/llvm-symbolizer

    package pkg-config
    package autoconf
    package automake
    package libtool
  fi

  set_cc gcc #-4.8
  set_cxx g++ #-4.8

  install_cmake
  install_boost

  install_gflags
  install_glog
  install_iptables_dev

  if [[ $DISTRO = "lucid" ]]; then
    gem_install --no-user-install fpm -v 1.3.3
  else
    # No clang++ on lucid
    set_cc clang
    set_cxx clang++
    gem_install fpm
  fi

  install_snappy
  install_libaptpkg

  if [[ $DISTRO = "lucid" ]]; then
    install_openssl
    install_bison
  else
    package bison
  fi

  install_thrift
  install_rocksdb
  install_yara
  install_asio
  install_cppnetlib
  install_google_benchmark

  # Need headers and PC macros
  package libgcrypt-dev
  package libdevmapper-dev
  install_libcryptsetup
  package libmagic-dev
  install_sleuthkit

  # Audit facility (kautitd) and netlink APIs
  package libaudit-dev

  if [[ $DISTRO = "lucid" ]]; then
    package python-argparse
    package python-jinja2
    package python-psutil
  fi
}
