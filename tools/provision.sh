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
FORMULA_DIR="$SCRIPT_DIR/provision/formula"

HOMEBREW_REPO="https://github.com/Homebrew/brew"
LINUXBREW_REPO="https://github.com/Linuxbrew/brew"

# Set the SHA1 commit hashes for the pinned homebrew Taps.
# Pinning allows determinism for bottle availability, expect to update often.
HOMEBREW_CORE="941ca36839ea354031846d73ad538e1e44e673f4"
LINUXBREW_CORE="abc5c5782c5850f2deff1f3d463945f90f2feaac"
HOMEBREW_BREW="ac2cbd2137006ebfe84d8584ccdcb5d78c1130d9"
LINUXBREW_BREW="20bcce2c176469cec271b46d523eef1510217436"

# If the world needs to be rebuilt, increase the version
DEPS_VERSION="4"

source "$SCRIPT_DIR/lib.sh"
source "$SCRIPT_DIR/provision/lib.sh"

function platform_linux_main() {
  # GCC 5x bootstrapping.
  brew_tool patchelf
  brew_tool zlib
  brew_tool binutils
  brew_tool linux-headers
  brew_tool gmp
  brew_tool mpfr
  brew_tool libmpc
  brew_tool isl
  brew_tool pkg-config

  # Build a bottle of a modern glibc.
  brew_tool osquery/osquery-local/glibc

  # Build a bottle for a legacy glibc.
  brew_tool osquery/osquery-local/glibc-legacy
  brew_tool osquery/osquery-local/zlib-legacy

  # GCC 5x.
  brew_tool osquery/osquery-local/gcc

  # Need LZMA for final builds.
  brew_tool osquery/osquery-local/xz
  brew_tool osquery/osquery-local/ncurses
  brew_tool osquery/osquery-local/bzip2

  brew_tool unzip
  brew_tool sqlite
  brew_tool makedepend
  brew_tool libidn
  brew_tool libedit
  brew_tool libtool
  brew_tool m4
  brew_tool autoconf
  brew_tool automake

  # OpenSSL is needed for the final build.
  brew_tool osquery/osquery-local/libxml2
  brew_tool osquery/osquery-local/openssl

  # Curl and Python are needed for LLVM mostly.
  brew_tool osquery/osquery-local/curl
  brew_tool osquery/osquery-local/python
  brew_tool osquery/osquery-local/cmake --without-docs

  # Linux library secondary dependencies.
  brew_tool osquery/osquery-local/berkeley-db
  brew_tool osquery/osquery-local/popt
  brew_tool osquery/osquery-local/beecrypt

  # LLVM/Clang.
  brew_tool osquery/osquery-local/llvm

  # Util-Linux provides libuuid.
  brew_dependency osquery/osquery-local/util-linux

  platform_posix_main

  # General Linux dependencies and custom formulas for table implementations.
  brew_dependency osquery/osquery-local/libgpg-error
  brew_dependency osquery/osquery-local/libdevmapper
  brew_dependency osquery/osquery-local/libaptpkg
  brew_dependency osquery/osquery-local/libiptables
  brew_dependency osquery/osquery-local/libgcrypt
  brew_dependency osquery/osquery-local/libcryptsetup
  brew_dependency osquery/osquery-local/libudev
  brew_dependency osquery/osquery-local/libaudit
  brew_dependency osquery/osquery-local/libdpkg
  brew_dependency osquery/osquery-local/librpm
}

function platform_darwin_main() {
  brew_tool xz
  brew_tool readline
  brew_tool sqlite
  brew_tool pkg-config
  brew_tool makedepend
  brew_tool ninja
  brew_tool osquery/osquery-local/cmake --without-docs
  brew_tool clang-format
  brew_tool autoconf
  brew_tool automake
  brew_tool libtool

  brew_dependency osquery/osquery-local/libxml2
  brew_dependency osquery/osquery-local/openssl
  brew_tool osquery/osquery-local/python
  brew_tool osquery/osquery-local/bison

  platform_posix_main
}

 function platform_posix_main() {
  # libarchive for file carving
  brew_dependency osquery/osquery-local/libarchive
  brew_dependency osquery/osquery-local/zstd

  # List of LLVM-compiled dependencies.
  brew_dependency osquery/osquery-local/lz4
  brew_dependency osquery/osquery-local/libmagic
  brew_dependency osquery/osquery-local/pcre
  brew_dependency osquery/osquery-local/boost
  brew_dependency osquery/osquery-local/asio
  brew_dependency osquery/osquery-local/cpp-netlib
  brew_dependency osquery/osquery-local/google-benchmark
  brew_dependency osquery/osquery-local/snappy
  brew_dependency osquery/osquery-local/sleuthkit
  brew_dependency osquery/osquery-local/thrift
  brew_dependency osquery/osquery-local/rocksdb
  brew_dependency osquery/osquery-local/gflags
  brew_dependency osquery/osquery-local/aws-sdk-cpp
  brew_dependency osquery/osquery-local/yara
  brew_dependency osquery/osquery-local/glog
  brew_dependency osquery/osquery-local/linenoise-ng
  brew_dependency osquery/osquery-local/augeas
  brew_dependency osquery/osquery-local/lldpd

  # POSIX-shared locally-managed tools.
  brew_dependency osquery/osquery-local/zzuf
  brew_dependency osquery/osquery-local/cppcheck
  brew_dependency osquery/osquery-local/ccache

  brew_dependency osquery/osquery-local/caf
  brew_dependency osquery/osquery-local/broker
}

function sysprep() {
  RUN_SYSPREP=false
  if [[ ! -z "$SKIP_DISTRO_MAIN" ]]; then
    if [[ "$SKIP_DISTRO_MAIN" = "False" || "$SKIP_DISTRO_MAIN" = "0" ]]; then
      RUN_SYSPREP=true
    fi
  fi

  if [[ ! "$RUN_SYSPREP" = "true" ]]; then
    return
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
    if [[ "$1" = "build" ]]; then
      distro_main
    fi
  else
    log "your $OS does not use a provision script"
  fi
}

function main() {
  ACTION=$1

  platform OS
  distro $OS DISTRO
  threads THREADS

  if ! hash sudo 2>/dev/null; then
    echo "Please install sudo in this machine"
    exit 1
  fi

  # Setup the osquery dependency directory.
  # One can use a non-build location using OSQUERY_DEPS=/path/to/deps
  if [[ ! -z "$OSQUERY_DEPS" ]]; then
    DEPS_DIR="$OSQUERY_DEPS"
  else
    DEPS_DIR="/usr/local/osquery"
  fi

  deps_version $DEPS_DIR $DEPS_VERSION

  if [[ "$ACTION" = "clean" ]]; then
    do_sudo rm -rf "$DEPS_DIR"
    return
  fi
  export DEPS_DIR=$DEPS_DIR

  # Setup the local ./build/DISTRO cmake build directory.
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
  elif [[ $OS = "freebsd" ]]; then
    BREW_TYPE="freebsd"
  else
    BREW_TYPE="linux"
  fi

  sysprep $ACTION

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

  if [[ ! "$BREW_TYPE" = "freebsd" ]]; then
    setup_brew "$DEPS_DIR" "$BREW_TYPE" "$ACTION"
    echo -n $DEPS_VERSION > $DEPS_DIR/DEPS_VERSION
  fi

  if [[ "$ACTION" = "bottle" ]]; then
    brew_bottle "$2"
    return
  elif [[ "$ACTION" = "uninstall" ]]; then
    brew_uninstall "$2"
    return
  elif [[ "$ACTION" = "install" ]]; then
    brew_dependency "$2"
    return
  fi

  if [[ ! -z "$OSQUERY_BUILD_DEPS" ]]; then
    log "[notice]"
    log "[notice] you are choosing to build dependencies instead of installing"
    log "[notice]"
  fi

  log "running unified platform initialization"
  brew_clear_cache
  if [[ "$BREW_TYPE" = "darwin" ]]; then
    platform_darwin_main
  elif [[ "$BREW_TYPE" = "linux" ]]; then
    platform_linux_main
  fi
  brew_clear_cache

  cd "$SCRIPT_DIR/../"

  # Additional compilations may occur for Python and Ruby
  export LIBRARY_PATH="$DEPS_DIR/legacy/lib:$DEPS_DIR/lib:$LIBRARY_PATH"
  set_cc clang
  set_cxx clang++

  # Pip may have just been installed.
  log "upgrading pip and installing python dependencies"
  PIP=`which pip`
  if [[ $OS = "freebsd" ]]; then
    PIP="sudo $PIP"
  fi
  $PIP install --upgrade pip
  # Pip may change locations after upgrade.
  PIP=`which pip`
  if [[ $OS = "freebsd" ]]; then
    PIP="sudo $PIP"
  fi
  $PIP install --no-cache-dir -I -r requirements.txt

  log "running auxiliary initialization"
  initialize $OS
}

check $1 "$2"
main $1 "$2"
