#!/usr/bin/env bash

function main_debian() {
  sudo apt-get update -y --no-install-recommends
  sudo apt-get upgrade -y --no-install-recommends

  package git-core
  package wget
  package g++-multilib

  if [[ $DISTRO == "wheezy" ]]; then
    set_cc gcc
    set_cxx g++

    export LIBRARY_PATH=/usr/lib/x86_64-linux-gnu
    install_gcc

    set_cc gcc
    set_cxx g++
  fi

  package unzip
  package build-essential
  package flex
  package devscripts
  package debhelper
  package python-pip
  package python-dev
  package ruby-dev
  package ruby1.8-dev
  package libffi-dev
  package rubygems
  package gcc
  package doxygen

  package autopoint
  package libssl-dev
  package liblzma-dev
  package uuid-dev
  package libpopt-dev
  package libdpkg-dev
  package libudev-dev
  package libblkid-dev
  package libbz2-dev
  package libreadline-dev
  package libcurl4-openssl-dev

  package libtool
  package autoconf
  package pkg-config
  package bison
  package clang

  if [[ $DISTRO == "wheezy" ]]; then
    # thrift requires automate 1.13 or later
    remove_package automake
    install_automake
  elif [[ $DISTRO == "jessie" ]]; then
    package automake
  fi

  if [[ $DISTRO == "wheezy" ]]; then
    gem_install fpm -v 1.3.3
  else
    set_cc clang
    set_cxx clang++
    gem_install fpm
  fi

  install_cmake
  install_boost
  install_gflags
  install_glog
  install_google_benchmark

  install_snappy
  install_rocksdb
  install_thrift
  install_yara
  install_asio
  install_cppnetlib
  install_sleuthkit

  # Need headers and PC macros
  package libgcrypt-dev
  package libdevmapper-dev
  package libaudit-dev
  package libmagic-dev

  install_libaptpkg
  install_iptables_dev
  install_libcryptsetup

  if [[ $DISTRO == "wheezy" ]]; then
    #pip has to be installed via easy_install
    easy_install pip
    # psutil and other things depending on gcc aren't
    # aware of Debian's multiarch and expect /usr/lib64
    sudo mkdir -p /usr/lib64
    sudo ln -sf /usr/lib/x86_64-linux-gnu/* /usr/lib64

    # libgcrpyt gets installed in /lib and cmake can't find
    # symlink it to /usr/local/lib
    sudo ln -sf /lib/x86_64-linux-gnu/libgcrypt.so /usr/local/lib/libgcrypt.so
    sudo ln -sf /lib/x86_64-linux-gnu/libgcrypt.a /usr/local/lib/libgcrypt.a
  fi

  install_aws_sdk
}
