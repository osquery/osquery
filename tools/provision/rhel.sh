#!/usr/bin/env bash

#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function main_rhel() {
  sudo yum update -y

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
  sudo subscription-manager repos --enable=rhel-7-server-optional-rpms
  package ruby-devel
  package rubygems

  if [[ $DISTRO = "rhel6" ]]; then
    package scl-utils
    package policycoreutils-python
    package
    package rhscl-devtoolset-3
    package devtoolset-3
    sudo scl enable devtoolset-3 bash
  elif [[ $DISTRO = "rhel7" ]]; then
    package gcc
    package binutils
    package gcc-c++
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
    install_thrift
  elif [[ $DISTRO = "rhel7" ]]; then
    package autoconf
    package automake
    package libtool
    install_thrift
  fi

  install_snappy
  install_rocksdb

  gem_install fpm
}
