#!/usr/bin/env bash

#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $SCRIPT_DIR/lib.sh

threads THREADS

cd $SCRIPT_DIR/../

# Builds dependencies
make deps
make clean

# Build osquery
make -j$THREADS

# Build osquery kernel
make kernel-build
make kernel-load

# Run code unit and integration tests
make test

make kernel-test

# Cleanup kernel
make kernel-unload || sudo reboot

