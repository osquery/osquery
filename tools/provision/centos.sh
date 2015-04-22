#!/usr/bin/env bash

#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function main_centos() {
  sudo yum update -y

  if [[ -z $(rpm -qa | grep 'kernel-headers-3') ]]; then
    if [[ $DISTRO = "centos6" ]]; then
      sudo rpm -iv https://osquery-packages.s3.amazonaws.com/deps/kernel-headers-3.10.0-123.9.3.el7.x86_64.rpm
    elif [[ $DISTRO = "centos7" ]]; then
      #package kernel-headers
      true
    fi
  fi

  package texinfo
  package wget
  package git-all
  package unzip
  package xz
  package xz-devel
  package epel-release
  package python-pip
  package python-devel
  package rpm-build
  package ruby-devel
  package rubygems

  if [[ $DISTRO = "centos6" ]]; then
    DEVTOOLS_VER=2
    pushd /etc/yum.repos.d
    if [[ ! -f /etc/yum.repos.d/devtools-2.repo ]]; then
      sudo wget http://people.centos.org/tru/devtools-2/devtools-2.repo
    fi
    popd
    
  elif [[ $DISTRO = "centos7" ]]; then
    DEVTOOLS_VER=3
    pushd /tmp
    if [[ ! -f /tmp/rhscl-devtoolset-3-epel-7-x86_64.noarch.rpm ]]; then
      sudo wget https://www.softwarecollections.org/en/scls/rhscl/devtoolset-3/epel-7-x86_64/download/rhscl-devtoolset-3-epel-7-x86_64.noarch.rpm
      sudo rpm -Uvh /tmp/rhscl-devtoolset-3-epel-7-x86_64.noarch.rpm
    fi
    popd

    package scl-utils
  fi

  package devtoolset-${DEVTOOLS_VER}-gcc
  package devtoolset-${DEVTOOLS_VER}-binutils
  package devtoolset-${DEVTOOLS_VER}-gcc-c++

  if [[ ! -e /usr/bin/gcc ]]; then
    sudo ln -s /opt/rh/devtoolset-${DEVTOOLS_VER}/root/usr/bin/gcc /usr/bin/gcc
  fi
  if [[ ! -e /usr/bin/g++ ]]; then
    sudo ln -s /opt/rh/devtoolset-${DEVTOOLS_VER}/root/usr/bin/gcc /usr/bin/g++
  fi

  source /opt/rh/devtoolset-${DEVTOOLS_VER}/enable
  if [[ ! -d /usr/lib/gcc ]]; then
    sudo ln -s /opt/rh/devtoolset-${DEVTOOLS_VER}/root/usr/lib/gcc /usr/lib/
  fi

  package clang
  package clang-devel

  set_cc clang
  set_cxx clang++

  package bzip2
  package bzip2-devel
  package openssl-devel
  package readline-devel
  package rpm-devel
  package rpm-build
  package libblkid-devel

  install_cmake
  install_boost

  if [[ $DISTRO = "centos6" ]]; then
    package libudev-devel
  elif [[ $DISTRO = "centos7" ]]; then
    package systemd-devel
  fi

  install_gflags

  package doxygen
  package byacc
  package flex
  package bison

  remove_package libunwind-devel

  if [[ $DISTRO = "centos6" ]]; then
    install_autoconf
    install_automake
    install_libtool
  elif [[ $DISTRO = "centos7" ]]; then
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
