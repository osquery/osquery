#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function main_freebsd() {
  sudo pkg update
  sudo pkg upgrade -y

  package gmake
  package cmake
  package git
  package python
  package py27-pip
  package glog
  package snappy
  package rocksdb
  package thrift
  package thrift-cpp
  package yara
  package boost-libs
  package cpp-netlib
  package magic
  install_aws_sdk
}
