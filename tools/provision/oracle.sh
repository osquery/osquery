#!/usr/bin/env bash

#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function main_oracle() {
  if [[ $DISTRO = "oracle5" ]]; then
    # Install the Fedora EPEL yum repository.
    sudo cp $FILES_DIR/oracle5.epel.repo /etc/yum.repos.d/
    sudo cp $FILES_DIR/RPM-GPG-KEY-EPEL /etc/pki/rpm-gpg/
    package epel-release -y
  fi

  sudo yum update -y

  package texinfo
  package wget
  package git-all
  package unzip
  package xz
  package xz-devel
  package python-devel
  package rpm-build
  package bzip2
  package bzip2-devel
  package openssl-devel
  package readline-devel
  package rpm-devel

  # Not needed, libblkid.a already installed.
  #package libblkid-devel

  if [[ $DISTRO = "oracle5" ]]; then
    package gcc
    install_gcc
  elif [[ $DISTRO = "oracle6" ]]; then
    # Install the CentOS6 Devtools-2 yum repository.
    sudo cp $FILES_DIR/centos6.devtools-2.repo /etc/yum.repos.d/

    package devtoolset-2-gcc
    package devtoolset-2-binutils
    package devtoolset-2-gcc-c++

    if [[ ! -e /usr/bin/gcc ]]; then
      sudo ln -s /opt/rh/devtoolset-2/root/usr/bin/gcc /usr/bin/gcc
    fi
    if [[ ! -e /usr/bin/g++ ]]; then
      sudo ln -s /opt/rh/devtoolset-2/root/usr/bin/gcc /usr/bin/g++
    fi

    source /opt/rh/devtoolset-2/enable
    if [[ ! -d /usr/lib/gcc ]]; then
      sudo ln -s /opt/rh/devtoolset-2/root/usr/lib/gcc /usr/lib/
    fi
  else
    package gcc
    package binutils
    package gcc-c++
  fi

  if [[ $DISTRO = "oracle5" ]]; then
    set_cc gcc
    set_cxx g++
  else
    package clang
    package clang-devel

    set_cc clang
    set_cxx clang++
  fi

  install_cmake
  install_boost

  if [[ $DISTRO = "oracle5" ]]; then
    package cryptsetup-luks-devel
    install_udev_devel_095
  elif [[ $DISTRO = "oracle6" ]]; then
    package libudev-devel
  fi

  install_gflags
  install_iptables_dev

  package doxygen
  package byacc
  package flex
  package bison

  if [[ $DISTRO = "oracle5" || $DISTRO = "oracle6" ]]; then
    remove_package autoconf
    remove_package automake
    remove_package libtool

    install_autoconf
    install_automake
    install_libtool
  else
    package autoconf
    package automake
    package libtool
  fi

  install_snappy
  install_rocksdb
  install_thrift
  install_yara

  if [[ $DISTRO = "oracle5" ]]; then
    # Install python26 and pip from PyPA.
    package python26
    package python26-devel
    install_pip python2.6

    # Install ruby 1.8.7/gems.
    install_ruby
  else
    package python-pip
    package ruby-devel
    package rubygems
  fi

  package file-libs

  gem_install fpm
}
