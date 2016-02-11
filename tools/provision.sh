#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

set -e

CFLAGS="-fPIE -fPIC -O2 -DNDEBUG -march=x86-64 -mno-avx"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR="$SCRIPT_DIR/../build"
WORKING_DIR="/tmp/osquery-provisioning"
FILES_DIR="$SCRIPT_DIR/provision/files"
DEPS_URL=https://osquery-packages.s3.amazonaws.com/deps
export PATH="$PATH:/usr/local/bin"

source "$SCRIPT_DIR/lib.sh"
source "$SCRIPT_DIR/provision/lib.sh"

function main() {
  platform OS
  distro $OS DISTRO
  threads THREADS

  if ! hash sudo 2>/dev/null; then
   echo "Please install sudo in this machine"
   exit 0
  fi

  if [[ $1 = "get_platform" ]]; then
    echo "$OS;$DISTRO"
    return 0
  fi

  mkdir -p "$WORKING_DIR"
  if [[ ! -z "$SUDO_USER" ]]; then
    echo "chown -h $SUDO_USER $BUILD_DIR/*"
    chown -h $SUDO_USER:$SUDO_GID "$BUILD_DIR" || true
    if [[ $OS = "linux" ]]; then
      chown -h $SUDO_USER:$SUDO_GID "$BUILD_DIR/linux" || true
    fi
    chown $SUDO_USER:$SUDO_GID "$WORKING_DIR" > /dev/null 2>&1 || true
  fi
  cd "$WORKING_DIR"

  if [[ $OS = "oracle" ]]; then
    log "detected oracle ($DISTRO)"
    source "$SCRIPT_DIR/provision/oracle.sh"
    main_oracle
  elif [[ $OS = "centos" ]]; then
    log "detected centos ($DISTRO)"
    source "$SCRIPT_DIR/provision/centos.sh"
    main_centos
  elif [[ $OS = "rhel" ]]; then
    log "detected rhel ($DISTRO)"
    source "$SCRIPT_DIR/provision/rhel.sh"
    main_rhel
  elif [[ $OS = "amazon" ]]; then
    log "detected amazon ($DISTRO)"
    source "$SCRIPT_DIR/provision/amazon.sh"
    main_amazon
  elif [[ $OS = "ubuntu" ]]; then
    log "detected ubuntu ($DISTRO)"
    source "$SCRIPT_DIR/provision/ubuntu.sh"
    main_ubuntu
  elif [[ $OS = "darwin" ]]; then
    log "detected mac os x ($DISTRO)"
    source "$SCRIPT_DIR/provision/darwin.sh"
    main_darwin
  elif [[ $OS = "freebsd" ]]; then
    log "detected freebsd ($DISTRO)"
    source "$SCRIPT_DIR/provision/freebsd.sh"
    main_freebsd
  elif [[ $OS = "fedora" ]]; then
    log "detected fedora ($DISTRO)"
    source "$SCRIPT_DIR/provision/fedora.sh"
    main_fedora
  elif [[ $OS = "debian" ]]; then
    log "detected debian ($DISTRO)"
    source "$SCRIPT_DIR/provision/debian.sh"
    main_debian
  else
    fatal "could not detect the current operating system. exiting."
  fi

  cd "$SCRIPT_DIR/../"

  sudo pip install --upgrade pip
  sudo pip install -r requirements.txt

  initialize $OS
}

check $1 $2
main $1
