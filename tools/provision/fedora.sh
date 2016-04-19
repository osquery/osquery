#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function main_fedora() {
  sudo dnf update -y

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
  package gcc
  package binutils
  package gcc-c++
  package clang
  package clang-devel

  set_cc clang
  set_cxx clang++

  if [[ $DISTRO -lt "22" ]]; then
    install_cmake
  else
    package cmake
  fi

  package doxygen
  package byacc
  package flex
  package bison
  package autoconf
  package automake
  package libtool

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
  package libgcrypt-devel
  package gettext-devel

  install_device_mapper
  install_iptables_dev
  install_libcryptsetup

  gem_install fpm

  install_aws_sdk
}
