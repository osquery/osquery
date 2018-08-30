#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

LIB_SCRIPT_DIR=$(dirname "${BASH_SOURCE[0]}")

# For OS X, define the distro that builds the kernel extension.
DARWIN_KERNEL_VERSION="10.11"

function platform() {
  local  __out=$1
  FAMILY=$(python "$LIB_SCRIPT_DIR/get_platform.py" --family)
  eval $__out=$(python "$LIB_SCRIPT_DIR/get_platform.py" --platform)
}

function _platform() {
  platform PLATFORM
  echo $PLATFORM
}

function distro() {
  local __out=$2
  eval $__out=$(python "$LIB_SCRIPT_DIR/get_platform.py" --distro)
}

function _distro() {
  distro $1 DISTRO
  echo $DISTRO
}

function threads() {
  local __out=$1
  platform OS
  if [[ $FAMILY = "redhat" ]] || [[ $FAMILY = "debian" ]] || [[ $FAMILY = "suse" ]]; then
    eval $__out=`cat /proc/cpuinfo | grep processor | wc -l`
  elif [[ $OS = "darwin" ]]; then
    eval $__out=`sysctl hw.ncpu | awk '{print $2}'`
  elif [[ $OS = "freebsd" ]]; then
    eval $__out=`sysctl -n kern.smp.cpus`
  else
    eval $__out=`nproc`
  fi
}

function log() {
  echo "[+] $1"
}

function fatal() {
  echo "[!] $1"
  exit 1
}

function set_cxx() {
  export CXX=$1
  export CMAKE_CXX_COMPILER=$1
}

function add_cxx_flag() {
  export CXXFLAGS="$CXXFLAGS $1"
  export CMAKE_CXX_FLAGS="$CMAKE_CXX_FLAGS $1"
}

function set_cc() {
  export CC=$1
  export CMAKE_C_COMPILER=$1
}

function do_sudo() {
  if [[ "$OSQUERY_NOSUDO" = "True" ]]; then
    $@
  else
    ARGS="$@"
    log "requesting sudo: $ARGS"
    sudo $@
  fi
}

function contains_element() {
  local e
  for e in "${@:2}"; do [[ "$e" == "$1" ]] && return 0; done
  return 1
}

function in_ec2() {
  if [[ -d /home/ec2-user ]]; then
    return 0
  else
    return 1
  fi
}

function checkout_thirdparty() {
  # Reset any work or artifacts from build tests in TP.
  (cd third-party && git reset --hard HEAD)
  git submodule init
  git submodule update
}

function build_target() {
  threads THREADS

  # Clean previous build artifacts.
  $MAKE distclean

  # Build osquery.
  if [[ -z "$RUN_TARGET" ]]; then
    $MAKE -j$THREADS
  else
    $MAKE $RUN_TARGET -j$THREADS
  fi
}

function test_target() {
  if [[ "$RUN_TARGET" = "debug" ]]; then
    $MAKE test_debug
  else
    $MAKE test
  fi
}

function check_deterministic() {
  # Expect the project to have been built.
  ALIAS=$DISTRO
  if [[ "$OS" = "darwin" ]]; then
    ALIAS=darwin
  fi
  DAEMON=build/$ALIAS/osquery/osqueryd
  strip $DAEMON
  RUN1=$(shasum -a 256 $DAEMON)

  # Build again.
  $MAKE distclean
  build_target

  strip $DAEMON
  RUN2=$(shasum -a 256 $DAEMON)
  echo "Initial build: $RUN1"
  echo " Second build: $RUN2"
  if [[ "$RUN1" = "$RUN2" ]]; then
    exit 0
  fi

  # The build is not deterministic.
  exit 1
}

function initialize() {
  DISTRO=$1
  checkout_thirdparty

  # Remove any previously-cached variables
  rm build/$DISTRO/CMakeCache.txt >/dev/null 2>&1 || true
}

function build() {
  platform PLATFORM
  distro $PLATFORM DISTRO

  MAKE=make
  if [[ "$PLATFORM" = "freebsd" ]]; then
    MAKE=gmake
  fi

  RUN_TESTS=$1

  cd $LIB_SCRIPT_DIR/../

  # Run build host provisions and install library dependencies.
  if [[ ! -z $RUN_BUILD_DEPS ]]; then
    $MAKE deps
  else
    initialize $DISTRO
  fi

  # Build osquery.
  build_target

  if [[ ! -z "$RUN_DETERMINISTIC" ]]; then
    check_deterministic
  fi

  if [[ $RUN_TESTS = true ]]; then
    # Run code unit and integration tests.
    test_target
  fi
}
