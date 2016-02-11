#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

ORACLE_RELEASE=/etc/oracle-release
SYSTEM_RELEASE=/etc/system-release
LSB_RELEASE=/etc/lsb-release
DEBIAN_VERSION=/etc/debian_version

function platform() {
  local  __out=$1
  if [[ -f "$ORACLE_RELEASE" ]]; then
    FAMILY="redhat"
    eval $__out="oracle"
  elif [[ -n `grep -o "CentOS" $SYSTEM_RELEASE 2>/dev/null` ]]; then
    FAMILY="redhat"
    eval $__out="centos"
  elif [[ -n `grep -o "Red Hat Enterprise" $SYSTEM_RELEASE 2>/dev/null` ]]; then
    FAMILY="redhat"
    eval $__out="rhel"
  elif [[ -n `grep -o "Amazon Linux" $SYSTEM_RELEASE 2>/dev/null` ]]; then
    FAMILY="redhat"
    eval $__out="amazon"
  elif [[ -f "$LSB_RELEASE" ]] && grep -q 'DISTRIB_ID=Ubuntu' $LSB_RELEASE; then
    FAMILY="debian"
    eval $__out="ubuntu"
  elif [[ -n `grep -o "Fedora" $SYSTEM_RELEASE 2>/dev/null` ]]; then
    FAMILY="redhat"
    eval $__out="fedora"
  elif [[ -f "$DEBIAN_VERSION" ]]; then
    FAMILY="debian"
    eval $__out="debian"
  else
    eval $__out=`uname -s | tr '[:upper:]' '[:lower:]'`
  fi
}

function _platform() {
  platform PLATFORM
  echo $PLATFORM
}

function distro() {
  local __out=$2
  if [[ $1 = "oracle" ]]; then
    eval $__out=`grep -o "release [5-7]" $SYSTEM_RELEASE | sed 's/release /oracle/g'`
  elif [[ $1 = "centos" ]]; then
    eval $__out=`grep -o "release [6-7]" $SYSTEM_RELEASE | sed 's/release /centos/g'`
  elif [[ $1 = "rhel" ]]; then
    eval $__out=`grep -o "release [6-7]" $SYSTEM_RELEASE | sed 's/release /rhel/g'`
  elif [[ $1 = "amazon" ]]; then
    eval $__out=`grep -o "release 20[12][0-9]\.[0-9][0-9]" $SYSTEM_RELEASE | sed 's/release /amazon/g'`
  elif [[ $1 = "ubuntu" ]]; then
    eval $__out=`awk -F= '/DISTRIB_CODENAME/ { print $2 }' $LSB_RELEASE`
  elif [[ $1 = "darwin" ]]; then
    eval $__out=`sw_vers -productVersion | awk -F '.' '{print $1 "." $2}'`
  elif [[ $1 = "fedora" ]]; then
    eval $__out=`cat /etc/system-release | cut -d" " -f3`
  elif [[ $1 = "debian" ]]; then
    eval $__out="`lsb_release -cs`"
  elif [[ $1 = "freebsd" ]]; then
    eval $__out=`uname -r | awk -F '-' '{print $1}'`
  else
    eval $__out="unknown_version"
  fi
}

function _distro() {
  distro $1 DISTRO
  echo $DISTRO
}

function threads() {
  local __out=$1
  platform OS
  if [[ $FAMILY = "redhat" ]] || [[ $FAMILY = "debian" ]]; then
    eval $__out=`cat /proc/cpuinfo | grep processor | wc -l`
  elif [[ $OS = "darwin" ]]; then
    eval $__out=`sysctl hw.ncpu | awk '{print $2}'`
  elif [[ $OS = "freebsd" ]]; then
    eval $__out=`sysctl -n kern.smp.cpus`
  else
    eval $__out=1
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

function build_kernel_cleanup() {
  # Cleanup kernel
  $MAKE kernel-unload || sudo reboot
}

function initialize() {
  DISTRO=$1

  # Reset any work or artifacts from build tests in TP.
  (cd third-party && git reset --hard HEAD)
  git submodule init
  git submodule update

  # Remove any previously-cached variables
  rm build/$DISTRO/CMakeCache.txt >/dev/null 2>&1 || true
}

function build() {
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

  RUN_TESTS=$1

  cd $SCRIPT_DIR/../

  # Run build host provisions and install library dependencies.
  if [[ ! -z $RUN_BUILD_DEPS ]]; then
    $MAKE deps
  else
    initialize $DISTRO
  fi

  # Clean previous build artifacts.
  $MAKE clean

  # Build osquery.
  $MAKE -j$THREADS

  if [[ $BUILD_KERNEL = 1 ]]; then
    # Build osquery kernel (optional).
    $MAKE kernel-build

    # Setup cleanup code for catastrophic test failures.
    trap build_kernel_cleanup EXIT INT TERM

    # Load osquery kernel (optional).
    $MAKE kernel-load
  fi

  if [[ $RUN_TESTS = true ]]; then
    # Run code unit and integration tests.
    $MAKE test/fast

    if [[ $BUILD_KERNEL = 1 ]]; then
      # Run kernel unit and integration tests (optional).
      $MAKE kernel-test/fast
    fi
  fi
}
