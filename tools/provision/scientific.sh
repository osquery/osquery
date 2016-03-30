#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function main_scientific() {
  sudo yum update -y
  package epel-release -y

  package texinfo
  package wget
  package git-all
  package unzip
  package xz
  package xz-devel
  package python-pip
  package python-devel
  package rpm-build
  package ruby
  package ruby-devel
  package rubygems
  package bzip2
  package bzip2-devel
  package openssl-devel
  package readline-devel
  package rpm-devel
  package libblkid-devel

  if [[ $DISTRO = "scientific6" ]]; then
    # Install the SL6 Devtools-2 yum repository.
    sudo cp $FILES_DIR/scientific6.devtoolset.repo /etc/yum.repos.d/

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
  elif [[ $DISTRO = "scientific7" ]]; then
    package gcc
    package binutils
    package gcc-c++
  fi

  package clang
  package clang-devel

  install_cmake

  set_cc clang
  set_cxx clang++

  if [[ $DISTRO = "scientific6" ]]; then
    package libudev-devel
  fi

  package doxygen
  package byacc
  package flex

  if [[ $DISTRO = "scientific6" ]]; then
    remove_package autoconf
    remove_package automake
    remove_package libtool

    export M4="/usr/bin/m4"
    install_autoconf
    install_automake
    install_libtool

    install_bison

    package file-libs
  elif [[ $DISTRO = "scientific7" ]]; then
    package autoconf
    package automake
    package libtool
    package file-devel
    package systemd-devel
    package bison
  fi

  install_boost
  install_gflags
  install_glog
  install_google_benchmark

  install_snappy
  install_rocksdb
  install_thrift
  install_yara
  install_asio
  install_cppnetlib
  install_sleuthkit

  # Device mapper uses the exact version as the ABI.
  # We will build and install a static version.
  remove_package device-mapper-devel
  install_device_mapper

  package libgcrypt-devel
  package gettext-devel
  install_libcryptsetup
  install_iptables_dev

  package audit-libs-devel
  package audit-libs-static

  gem_install fpm
}
