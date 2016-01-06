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
  package libtool
  package autoconf
  package pkg-config
  
  package bison
  package flex
  package devscripts
  package debhelper
  package python-pip
  package python-dev

  package ruby-dev
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
  
  package iptables-dev

  package libsnappy-dev
  package libgflags-dev

  package libaudit-dev
  package libmagic-dev
  
  if [[ $DISTRO == "wheezy" ]]; then
    install_cmake
    install_boost

    # thrift requires automate 1.13 or later
    remove_package automake
    install_automake
  elif [[ $DISTRO == "jessie" ]]; then 
    package cmake
    package libboost-all-dev
    package automake
  fi 

  install_google_benchmark

  package rubygems
  gem_install fpm

  install_thrift
  install_rocksdb 
  install_yara
  install_cppnetlib
  install_gflags
  install_sleuthkit
  
  # Need headers and PC macros
  package libgcrypt-dev
  package libdevmapper-dev

  package libcryptsetup-dev

  if [[ $DISTRO == "wheezy" ]]; then
    # psutil and other things depending on gcc aren't
    # aware of Debian's multiarch and expect /usr/lib64
    sudo mkdir -p /usr/lib64
    sudo ln -sf /usr/lib/x86_64-linux-gnu/* /usr/lib64
    
    # libgcrpyt gets installed in /lib and cmake can't find
    # symlink it to /usr/local/lib
    sudo ln -sf /lib/x86_64-linux-gnu/libgcrypt.so /usr/local/lib/libgcrypt.so
    sudo ln -sf /lib/x86_64-linux-gnu/libgcrypt.a /usr/local/lib/libgcrypt.a
  fi
}
