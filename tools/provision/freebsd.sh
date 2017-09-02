#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function distro_main() {
  do_sudo pkg update
  do_sudo pkg upgrade -y

  # Use it with caution -- unless the dependency is newly added
  # and the pre-built package is not ready yet.
  # do_sudo portsnap --interactive fetch update

  # Build requirements.
  package gmake
  package cmake
  package git
  package python
  package py27-pip

  # Core development requirements.
  package glog
  package thrift
  package thrift-cpp
  package boost-libs
  package magic
  package rocksdb
  package asio
  package cpp-netlib
  package linenoise-ng
  package rapidjson
  package zstd

  # Non-optional features.
  package augeas

  # Optional features.
  package sleuthkit
  package yara
  package aws-sdk-cpp
  package lldpd

  # For testing
  package doxygen
  package valgrind
}
