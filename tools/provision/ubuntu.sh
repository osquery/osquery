#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed in accordance with the terms specified in
#  the LICENSE file found in the root directory of this source tree.

function distro_main() {
  do_sudo apt-get -y update

  package autopoint
  package automake
  package autoconf
  package libtool
  package pkg-config
  package g++
  package curl
  package bison
  package flex

  package ruby
  package ruby-dev
  package bsdtar
  package doxygen
  package valgrind

  # Needed to build thrift
  package libfl-dev

  # Needed to build LLVM
  package cmake

  # Needed for libcryptsetup
  package autotools-dev

  # Needed for python
  package unzip

  GEM=`which gem`
  do_sudo $GEM install --no-ri --no-rdoc fpm
}
