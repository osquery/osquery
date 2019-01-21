#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed as defined on the LICENSE file found in the
#  root directory of this source tree.

function distro_main() {
  do_sudo apt-get -y update

  package doxygen
  package valgrind
}
