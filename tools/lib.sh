#!/usr/bin/env bash

#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

ORACLE_RELEASE=/etc/oracle-release
SYSTEM_RELEASE=/etc/system-release
UBUNTU_RELEASE=/etc/lsb-release

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
  elif [[ -f "$UBUNTU_RELEASE" ]]; then
    FAMILY="debian"
    eval $__out="ubuntu"
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
    eval $__out=`grep DISTRIB_CODENAME $UBUNTU_RELEASE | awk -F'=' '{print $2}'`
  elif [[ $1 = "darwin" ]]; then
    eval $__out=`sw_vers -productVersion | awk -F '.' '{print $1 "." $2}'`
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
