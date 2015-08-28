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

function enable_repo() {
  if sudo yum-config-manager --enable $1; then
    echo "RHN subscription repo enabled: $1"
  else
    echo "WARNING: Could not enable RHN a repo: $1!"
    echo "WARNING: Please run: sudo yum-config-manager repos --enable $1"
    echo "WARNING: Continuing dependency installation, this may fail..."
  fi
}

function main_rhel() {
  if [[ -z `rpm -qa epel-release` ]]; then
    if [[ $DISTRO = "rhel6" ]]; then
      sudo rpm -iv $DEPS_URL/epel-release-6-8.noarch.rpm
    elif [[ $DISTRO = "rhel7" ]]; then
      sudo rpm -iv $DEPS_URL/epel-release-7-5.noarch.rpm
    fi
  fi

  if [[ $DISTRO = "rhel6" ]]; then
    if in_ec2; then
      enable_repo rhui-REGION-rhel-server-rhscl
    else
      enable_repo rhel-6-server-optional-rpms
    fi
  elif [[ $DISTRO = "rhel7" ]]; then
    if in_ec2; then
      enable_repo rhui-REGION-rhel-server-optional
    else
      enable_repo rhel-7-server-optional-rpms
    fi
  fi

  sudo yum update -y

  package texinfo
  package wget
  package git
  package unzip
  package xz
  package xz-devel
  package python-pip
  package python-devel
  package rpm-build
  package ruby
  package ruby-devel
  package rubygems
  package bzip2
  package bzip2-devel
  package openssl-devel
  package readline-devel
  package rpm-devel
  package rpm-build
  package libblkid-devel

  if [[ $DISTRO = "rhel6" ]]; then
    package scl-utils
    package policycoreutils-python
    package devtoolset-3-runtime
    package devtoolset-3-binutils
    package devtoolset-3-libstdc++-devel
    package devtoolset-3-gcc-4.9.2
    package devtoolset-3-gcc-c++-4.9.2
    source /opt/rh/devtoolset-3/enable
  elif [[ $DISTRO = "rhel7" ]]; then
    package gcc
    package binutils
    package gcc-c++
  fi

  package clang
  package clang-devel

  set_cc gcc
  set_cxx g++

  install_cmake
  install_boost

  if [[ $DISTRO = "rhel6" ]]; then
    package libudev-devel
    package cryptsetup-luks-devel
  elif [[ $DISTRO = "rhel7" ]]; then
    package cryptsetup-devel
  fi

  install_gflags
  install_iptables_dev

  package doxygen
  package byacc
  package flex
  package bison

  if [[ $DISTRO = "rhel6" ]]; then
    remove_package autoconf
    remove_package automake
    remove_package libtool

    install_autoconf
    install_automake
    install_libtool

    package file-libs
  elif [[ $DISTRO = "rhel7" ]]; then
    package autoconf
    package automake
    package libtool
    package file-devel
  fi

  install_snappy
  install_rocksdb
  install_thrift
  install_yara

  package device-mapper-devel
  package libgcrypt-devel
  package gettext-devel
  install_libcryptsetup

  gem_install fpm
}
