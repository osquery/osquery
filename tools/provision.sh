#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

set -e

# Helpful defines for the provisioning process.
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BUILD_DIR="$SCRIPT_DIR/../build"
WORKING_DIR="/tmp/osquery-provisioning" # no longer needed
FILES_DIR="$SCRIPT_DIR/provision/files" # maybe needed
FORMULA_DIR="$SCRIPT_DIR/provision/formula"
DEPS_URL=https://osquery-packages.s3.amazonaws.com/deps # no longer needed

HOMEBREW_REPO="https://github.com/Homebrew/brew"
LINUXBREW_REPO="https://github.com/Linuxbrew/brew"

# Set the SHA1 commit hashes for the pinned homebrew Taps.
# Pinning allows determinism for bottle availability, expect to update often.
HOMEBREW_CORE="14eaa685169edf4283e1dadd5818646f67d09f30"
LINUXBREW_CORE="600e1460c79b9cf6945e87cb5374b9202db1f6a9"
HOMEBREW_DUPES="36b6b7cd76a482319611eeb71e51f3134018a21c"
LINUXBREW_DUPES="83cad3d474e6d245cd543521061bba976529e5df"

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

  # Setup the osquery dependency directory.
  # One can use a non-build location using OSQUERY_DEPS=/path/to/deps
  if [[ -e "$OSQUERY_DEPS" ]]; then
    DEPS_DIR="$OSQUERY_DEPS"
  else
    DEPS_DIR="/usr/local/osquery"
  fi

  if [[ "$1" = "clean" ]]; then
    do_sudo rm -rf "$DEPS_DIR"
    return
  fi

  # Setup the local ./build/DISTRO cmake build directory.
  mkdir -p "$WORKING_DIR"
  if [[ ! -z "$SUDO_USER" ]]; then
    echo "chown -h $SUDO_USER $BUILD_DIR/*"
    chown -h $SUDO_USER:$SUDO_GID "$BUILD_DIR" || true
    if [[ $OS = "linux" ]]; then
      chown -h $SUDO_USER:$SUDO_GID "$BUILD_DIR/linux" || true
    fi
    chown $SUDO_USER:$SUDO_GID "$WORKING_DIR" > /dev/null 2>&1 || true
  fi

  # Provisioning uses either Linux or Home (OS X) brew.
  if [[ $OS = "darwin" ]]; then
    BREW_TYPE="darwin"
  else
    BREW_TYPE="linux"
  fi

  # Each OS/Distro may have specific provisioning needs.
  # These scripts are optional and should installed the needed packages for:
  # 1. A basic ruby interpreter to run brew
  # 2. A GCC compiler to compile a modern glibc/GCC and legacy glibc.
  # 3. Curl, git, autotools, autopoint, and gawk.
  OS_SCRIPT="$SCRIPT_DIR/provision/$OS.sh"
  if [[ -f "$OS_SCRIPT" ]]; then
    log "found $OS provision script: $OS_SCRIPT"
    source "$OS_SCRIPT"
    if [[ -z "$SKIP_DISTRO_MAIN" ]]; then
      distro_main
    fi
  else
    log "your $OS does not use a provision script"
  fi

  # The dependency directory (DEPS_DIR) will contain our legacy runtime glibc
  # and various compilers/library dependencies.
  if [[ ! -d "$DEPS_DIR" ]]; then
    log "creating build dir: $DEPS_DIR"
    do_sudo mkdir -p "$DEPS_DIR"
    do_sudo chown $USER "$DEPS_DIR" > /dev/null 2>&1 || true
  fi
  cd "$DEPS_DIR"

  # Finally run the setup of *brew, and checkout the needed Taps.
  # This will install a local tap using a symbol to the formula subdir here.
  export PATH="$DEPS_DIR/bin:$PATH"
  setup_brew "$DEPS_DIR" "$BREW_TYPE"

  if [[ ! -z "$OSQUERY_BUILD_DEPS" ]]; then
    log "[notice]"
    log "[notice] you are choosing to build dependencies instead of installing"
    log "[notice]"
  fi

  log "running unified platform initialization"
  if [[ "$BREW_TYPE" = "darwin" ]]; then
    platform_darwin_main
  else
    platform_linux_main

    # Additional compilations may occur for Python and Ruby
    export LIBRARY_PATH="$DEPS_DIR/lib:$DEPS_DIR/legacy/lib:$LIBRARY_PATH"
  fi
  cd "$SCRIPT_DIR/../"

  # Pip may have just been installed.
  log "upgrading pip and installing python dependencies"
  PIP=`which pip`
  $PIP install --upgrade pip
  # Pip may change locations after upgrade.
  PIP=`which pip`
  $PIP install -r requirements.txt

  log "running auxiliary initialization"
  initialize $OS
}

function platform_linux_main() {
  # GCC 5x bootstrapping.
  core_brew_tool patchelf
  core_brew_tool zlib
  core_brew_tool binutils
  core_brew_tool linux-headers

  # Build a bottle of a modern glibc.
  local_brew_tool glibc
  local_brew_postinstall glibc

  # Build a bottle for a legacy glibc.
  local_brew_tool glibc-legacy
  local_brew_postinstall glibc-legacy

  # Need LZMA for final builds.
  local_brew_tool xz

  # Additional GCC 5x bootstrapping.
  core_brew_tool gmp
  core_brew_tool mpfr
  core_brew_tool libmpc
  core_brew_tool isl
  brew_tool berkeley-db

  # GCC 5x.
  local_brew_tool gcc --with-glibc-legacy --without-fortran
  set_deps_compilers gcc

  # GCC-compiled (C) dependencies.
  brew_tool pkg-config

  # Build a bottle for ncurses
  local_brew_tool ncurses

  # Need BZIP/Readline for final build.
  local_brew_tool bzip2
  brew_tool unzip
  local_brew_tool readline
  brew_tool sqlite
  core_brew_tool makedepend
  core_brew_tool libidn

  # Build a bottle for perl and openssl.
  # OpenSSL is needed for the final build.
  # local_brew_tool perl -vd --without-test
  local_brew_tool openssl
  $BREW link --force openssl

  # LLVM dependencies.
  brew_tool libxml2
  brew_tool libedit
  brew_tool libtool
  brew_tool m4
  brew_tool bison

  # Need libgpg-error for final build.
  local_brew_tool libgpg-error

  # More LLVM dependencies.
  brew_tool popt
  brew_tool autoconf
  brew_tool automake

  # Curl and Python are needed for LLVM mostly.
  local_brew_tool curl
  local_brew_tool python
  local_brew_postinstall python
  local_brew_tool cmake --without-docs

  # LLVM/Clang.
  local_brew_tool llvm
  set_deps_compilers clang

  # Install custom formulas, build with LLVM/clang.
  local_brew_dependency boost
  local_brew_dependency asio
  local_brew_dependency cpp-netlib
  local_brew_dependency google-benchmark
  local_brew_dependency pcre
  local_brew_dependency lz4
  local_brew_dependency snappy
  local_brew_dependency sleuthkit
  local_brew_dependency libmagic
  local_brew_dependency thrift
  local_brew_dependency rocksdb
  local_brew_dependency gflags
  local_brew_dependency aws-sdk-cpp
  local_brew_dependency yara
  local_brew_dependency glog

  # Linux specific custom formulas.
  local_brew_dependency util-linux
  local_brew_dependency libdevmapper -vd
  local_brew_dependency libaptpkg
  local_brew_dependency libiptables
  local_brew_dependency libgcrypt
  local_brew_dependency libcryptsetup -vd
  local_brew_dependency libudev
  local_brew_dependency libaudit
  local_brew_dependency libdpkg

  ## The following section is a work in progress for librpm.
  # This will need NSS and NSPR
  # core_brew_tool nspr
  # local_brew_link nspr
  # core_brew_tool nss
  # Maybe autopoint for autogen.sh?
  # brew_tool gettext
  # core_brew_tool libarchive
  # local_brew_dependency librpm

  # Restore the compilers to GCC for the remainder of provisioning.
  set_deps_compilers gcc
}

function platform_darwin_main() {
  brew_tool xz
  brew_tool readline
  brew_tool sqlite
  core_brew_tool makedepend

  local_brew_dependency openssl --without-test
  $BREW link --force openssl

  brew_tool pkg-config
  brew_tool autoconf
  brew_tool automake
  brew_tool libtool
  brew_tool m4
  brew_tool bison
  local_brew_link bison

  local_brew_tool python
  local_brew_postinstall python
  local_brew_tool cmake --without-docs

  # List of LLVM-compiled dependencies.
  local_brew_dependency boost
  local_brew_dependency asio
  local_brew_dependency cpp-netlib
  local_brew_dependency google-benchmark
  local_brew_dependency pcre
  local_brew_dependency lz4
  local_brew_dependency snappy
  local_brew_dependency sleuthkit
  local_brew_dependency libmagic
  local_brew_dependency thrift
  local_brew_dependency rocksdb
  local_brew_dependency gflags
  local_brew_dependency aws-sdk-cpp
  local_brew_dependency yara
  local_brew_dependency glog
}

check $1 "$2"
main $1 "$2"
