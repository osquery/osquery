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
platform PLATFORM
distro $PLATFORM DISTRO

# Build kernel extension/module and tests.
BUILD_KERNEL=0
if [[ "$PLATFORM" = "darwin" ]]; then
  if [[ "$DISTRO" = "10.10" ]]; then
    BUILD_KERNEL=1
  fi
fi

MAKE=make
if [[ "$PLATFORM" = "freebsd" ]]; then
  MAKE=gmake
fi

cd $SCRIPT_DIR/../

function cleanUp() {
  # Cleanup kernel
  $MAKE kernel-unload || sudo reboot
}

# Run build host provisions and install library dependencies.
$MAKE deps

# Clean previous build artifacts.
$MAKE clean

# Build osquery.
$MAKE -j$THREADS

if [[ $BUILD_KERNEL = 1 ]]; then
  # Build osquery kernel (optional).
  $MAKE kernel-build

  # Setup cleanup code for catastrophic test failures.
  trap cleanUp EXIT INT TERM

  # Load osquery kernel (optional).
  $MAKE kernel-load
fi

# Request that tests include addition 'release' or 'package' units.
export RUN_RELEASE_TESTS=1

# Run code unit and integration tests.
$MAKE test/fast

if [[ $BUILD_KERNEL = 1 ]]; then
  # Run kernel unit and integration tests (optional).
  $MAKE kernel-test/fast
fi

exit 0
