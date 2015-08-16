#!/usr/bin/env bash

#  Copyright (c) 2014, Facebook, Inc.
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

  install_boost

  package libudev-devel
  package cryptsetup-luks-devel

  install_gflags
  install_iptables_dev

  package doxygen
  package byacc
  package flex
  package bison
  package file-libs

  remove_package libunwind-devel

  install_autoconf
  install_automake
  install_libtool

  install_snappy
  install_rocksdb
  install_thrift
  install_yara
  install_cppnetlib
  install_google_benchmark

  package audit-libs-devel
  package audit-libs-static

  gem_install fpm
}
