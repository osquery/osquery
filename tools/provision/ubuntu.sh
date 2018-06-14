#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

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

  # Needed to build LLVM
  package cmake

  # Needed for libcryptsetup
  package autotools-dev

  # Needed for python
  package unzip

  GEM=`which gem`
  do_sudo $GEM install --no-ri --no-rdoc fpm
}
