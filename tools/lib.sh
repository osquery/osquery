#!/usr/bin/env bash

#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function platform() {
  local  __resultvar=$1
  if [[ -f "/etc/redhat-release" ]]; then
    eval $__resultvar="centos"
  elif [[ -f "/etc/lsb-release" ]]; then
    eval $__resultvar="ubuntu"
  else
    eval $__resultvar=`uname -s | tr '[:upper:]' '[:lower:]'`
  fi
}

function distro() {
  local __resultvar=$2
  if [[ $1 = "centos" ]]; then
    eval $__resultvar=`cat /etc/redhat-release | grep -o "release [6-7]" | sed 's/release /centos/g'`
  elif [[ $1 = "ubuntu" ]]; then
    eval $__resultvar=`cat /etc/*-release | grep DISTRIB_CODENAME | awk -F '=' '{print $2}'`
  elif [[ $1 = "darwin" ]]; then
    eval $__resultvar=`sw_vers -productVersion | awk -F '.' '{print $1 "." $2}'`
  elif [[ $1 = "freebsd" ]]; then
    eval $__resultvar=`uname -r | awk -F '-' '{print $1}'`
  else
    eval $__resultvar="unknown_version"
  fi
}

function threads() {
  local __resultvar=$1
  platform OS
  if [ $OS = "centos" ] || [ $OS = "ubuntu" ]; then
    eval $__resultvar=`cat /proc/cpuinfo | grep processor | wc -l`
  elif [[ $OS = "darwin" ]]; then
    eval $__resultvar=`sysctl hw.ncpu | awk '{print $2}'`
  elif [[ $OS = "freebsd" ]]; then
    eval $__resultvar=`sysctl -n kern.smp.cpus`
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

