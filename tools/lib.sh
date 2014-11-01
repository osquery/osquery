#!/usr/bin/env bash

function platform() {
  local  __resultvar=$1
  if [[ -f "/etc/redhat-release" ]]; then
    eval $__resultvar="centos"
  elif [[ -f "/etc/debian_version" ]]; then
    eval $__resultvar="ubuntu"
  elif [[ -f "/etc/pf.conf" ]]; then
    eval $__resultvar="darwin"
  fi
}

function threads() {
  local __resultvar=$1
  platform OS
  if [ $OS = "centos" ] || [ $OS = "ubuntu" ]; then
    eval $__resultvar=`cat /proc/cpuinfo | grep processor | wc -l`
  elif [[ $OS = "darwin" ]]; then
    eval $__resultvar=`sysctl hw.ncpu | awk '{print $2}'`
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
