#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function main_arch() {
  sudo pacman -Syu

  package asio
  package audit
  package boost
  package boost-libs
  package clang
  package cmake
  package doxygen
  package gflags
  package git
  package google-glog
  package lsb-release
  package make
  package python
  package python-jinja
  package python-pip
  package sleuthkit
  package snappy
  package thrift
  package yara

  install_aws_sdk

  echo ""
  echo "The following packages need to be installed from the AUR:"
  echo "rocksdb rocksdb-static cpp-netlib magic"
  echo ""
}

