#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

function fetch_beast() {
  log "fetching boost.beast"
  PATH_PREFIX=`dirname \`pkg query  %p/%n| grep boost-libs\``
  if [ -z $PATH_PREFIX ]
  then
    log "failed to install boost.beast"
    return
  fi

  VERSION_FILE="${PATH_PREFIX}/include/boost/beast/version.hpp"
  if [ -f "$VERSION_FILE" ]
  then
    version=`awk '{if ($2 == "BOOST_BEAST_VERSION") print $3}' $VERSION_FILE`
    if [ $version -ne 111 ]
    then
      pushd ${PATH_PREFIX}/include/boost/
      do_sudo rm -rf beast/ beast.hpp
      popd
    else
      log "boost.beast v111 already installed"
      return
    fi
  fi

  if [ -d "/tmp/beast" ]
    then
    rm -rf /tmp/beast
  fi

  pushd /tmp/ > /dev/null
  git clone https://github.com/uptycs-nishant/beast.git
  pushd beast/ > /dev/null
  git checkout v111
  pushd include/boost/ > /dev/null
  do_sudo mv -f beast/ beast.hpp ${PATH_PREFIX}/include/boost/
  popd > /dev/null
  popd > /dev/null
  popd > /dev/null
}

function distro_main() {
  do_sudo pkg update
  do_sudo pkg upgrade -y

  # Use it with caution -- unless the dependency is newly added
  # and the pre-built package is not ready yet.
  # do_sudo portsnap --interactive fetch update

  # Build requirements.
  package gmake
  package cmake
  package git
  package python
  package py27-pip

  # Core development requirements.
  package glog
  package thrift
  package thrift-cpp
  package boost-libs
  package magic
  package rocksdb-lite
  package asio
  package cpp-netlib
  package linenoise-ng
  package rapidjson
  package zstd

  # Non-optional features.
  package augeas

  # Optional features.
  package sleuthkit
  package yara
  package aws-sdk-cpp
  package lldpd

  # For testing
  package doxygen
  package valgrind

  # With an upgrade to boost-1.66
  # we can get rid of fetch_beast
  fetch_beast
}
