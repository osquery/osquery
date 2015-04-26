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
  sudo rm -Rf /var/lib/apt/lists/*
  sudo apt-get update
  sudo apt-get clean

  package wget
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

  if [[ $DISTRO = "precise" ]]; then
    package clang-3.4
    package clang-format-3.4
  else
    package clang-3.5
    package clang-format-3.5

    sudo ln -sf /usr/bin/clang-3.5 /usr/bin/clang
    sudo ln -sf /usr/bin/clang++-3.5 /usr/bin/clang++
    sudo ln -sf /usr/bin/clang-format-3.5 /usr/bin/clang-format
    sudo ln -sf /usr/bin/llvm-config-3.5 /usr/bin/llvm-config
  fi

  package librpm-dev
  package libdpkg-dev
  package libapt-pkg-dev
  package libudev-dev
  package libblkid-dev
  package libcryptsetup-dev
  package linux-headers-generic
  package ruby-dev
  package gcc
  package doxygen

  set_cc clang
  set_cxx clang++

  if [[ $DISTRO = "precise" ]]; then
    package rubygems
    package gcc-4.8
    package g++-4.8
    sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-4.8 150 \
      --slave /usr/bin/g++ g++ /usr/bin/g++-4.8
    install_boost
  else
    package libboost1.55-all-dev
  fi

  install_cmake
  install_gflags

  if [[ $DISTRO = "precise" ]]; then
    remove_package libunwind7-dev
  else
    remove_package libunwind8-dev
  fi

  package libsnappy-dev
  package libbz2-dev
  package libreadline-dev

  install_thrift
  install_rocksdb
  install_yara

  gem_install fpm
}
