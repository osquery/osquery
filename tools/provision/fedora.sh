#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function distro_main() {
  do_sudo dnf update -y

  package wget
  package git
  package unzip
  package gawk
  package xz
  package ruby
  package ruby-irb
  package gcc
  package bzip2
  package gettext-devel
  package bison
  package flex
  package doxygen
  package valgrind

  package rpm-devel
  package rpm-build
}
