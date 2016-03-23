#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function main_amazon() {

  sudo yum update -y

  package texinfo
  package wget
  package git-all
  package unzip
  package xz
  package xz-devel
  package epel-release
  package python-pip
  package python-devel
  package rpm-build
  package ruby-devel
  package rubygems

  package gcc
  package binutils
  package gcc-c++

  package clang
  package clang-devel

  package bzip2
  package bzip2-devel
  package openssl-devel
  package readline-devel
  package rpm-devel
  package rpm-build
  package libblkid-devel

  install_cmake

  set_cc clang
  set_cxx clang++

  package doxygen
  package byacc
  package flex
  package bison

  remove_package libunwind-devel

  install_autoconf
  install_automake
  install_libtool

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

  package file-libs
  package file-devel
  package libudev-devel
  package cryptsetup-luks-devel
  install_iptables_dev

  package audit-libs-devel
  package audit-libs-static

  gem_install fpm
}
