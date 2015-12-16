#!/usr/bin/env bash

#  Copyright (c) 2015, Facebook, Inc.
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
    install_boost
    install_iptables_dev
  else
    package cmake
    package boost-devel
    package boost-static
    package iptables-devel
  fi

  package doxygen
  package byacc
  package flex
  package bison
  package autoconf
  package automake
  package libtool

  if [[ $DISTRO -lt "22" ]]; then
    install_snappy
    install_thrift
  else
    package snappy
    package snappy-devel
    package thrift
    package thrift-devel
  fi

  install_gflags
  install_rocksdb
  install_yara
  install_cppnetlib
  install_google_benchmark

  package device-mapper-devel
  package libgcrypt-devel
  package gettext-devel

  install_libcryptsetup
  install_sleuthkit

  gem_install fpm
}
