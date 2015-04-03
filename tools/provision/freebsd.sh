#!/usr/bin/env bash

#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function main_freebsd() {
  package cmake
  package git
  package python
  package py27-pip
  package rocksdb
  package thrift-cpp
}
