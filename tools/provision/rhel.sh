#!/usr/bin/env bash

#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function require_channel() {
  local channel=$1
  # Check if developer channels exist
  DEV_EXISTS=`sudo rhn-channel -l | grep -o $channel || true`
  if [[ "$DEV_EXISTS" != "$channel" ]]; then
    echo ""
    echo "Action needed: "
    echo "You need the RHEL6 $channel channel installed."
    echo "sudo rhn-channel --add --channel=$channel"
    echo ""
    exit 1
  fi
}

function main_rhel() {
  if [[ $DISTRO = "rhel6" ]]; then
    require_channel "rhel-x86_64-server-6-rhscl-1"
    require_channel "rhel-x86_64-server-optional-6"
  fi

  sudo yum update -y

  package git
  package texinfo
  package wget
  package git
  package unzip
  package xz
  package xz-devel
  package subscription-manager

  if [[ -z `rpm -qa epel-release` ]]; then
    if [[ $DISTRO = "rhel6" ]]; then
      sudo rpm -iv https://osquery-packages.s3.amazonaws.com/deps/epel-release-6-8.noarch.rpm
    elif [[ $DISTRO = "rhel7" ]]; then
      sudo rpm -iv https://osquery-packages.s3.amazonaws.com/deps/epel-release-7-5.noarch.rpm
    fi
  fi

  # This solves a problem with epel and how it retrieves packages
  sudo yum clean all
  sudo yum --disablerepo="epel" update nss

  package python-pip
  package python-devel
  package rpm-build
  package ruby
  package ruby-devel
  package rubygems

  if [[ $DISTRO = "rhel6" ]]; then
    package scl-utils
    package policycoreutils-python
    package devtoolset-3
    source /opt/rh/devtoolset-3/enable 
  elif [[ $DISTRO = "rhel7" ]]; then
    sudo subscription-manager repos --enable=rhel-7-server-optional-rpms
    package gcc
    package binutils
    package gcc-c++
  fi

  package clang
  package clang-devel

  if [[ $DISTRO = "rhel6" ]]; then
    # GCC is needed for glib/libstdc++ 4.9+
    set_cc gcc
    set_cxx g++
  elif [[ $DISTRO = "rhel7" ]]; then
    # Clang was built with a newer libstdc++
    set_cc clang
    set_cxx clang++
  fi

  package bzip2
  package bzip2-devel
  package openssl-devel
  package readline-devel
  package rpm-devel
  package rpm-build
  package libblkid-devel

  install_cmake
  install_boost

  if [[ $DISTRO = "rhel6" ]]; then
    package libudev-devel
  elif [[ $DISTRO = "rhel7" ]]; then
    package systemd-devel
  fi

  install_gflags

  package doxygen
  package byacc
  package flex
  package bison

  remove_package libunwind-devel

  if [[ $DISTRO = "rhel6" ]]; then
    install_autoconf
    install_automake
    install_libtool
  elif [[ $DISTRO = "rhel7" ]]; then
    package autoconf
    package automake
    package libtool
  fi

  install_snappy
  install_rocksdb
  install_thrift
  install_yara

  gem_install fpm
}
