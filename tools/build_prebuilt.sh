#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed in accordance with the terms specified in
#  the LICENSE file found in the root directory of this source tree.

set -e

# To setup in a CI or similar on Ubuntu 18.04/18.10
# sudo apt-get install automake pkg-config libtool autopoint bison flex xsltproc texinfo
# wget https://github.com/Kitware/CMake/releases/download/v3.14.5/cmake-3.14.5-Linux-x86_64.tar.gz
# sudo tar xvf cmake-3.14.5-Linux-x86_64.tar.gz -C /usr/local --strip 1
# wget https://github.com/theopolis/build-anywhere/releases/download/v5/x86_64-anywhere-linux-gnu-v5.tar.xz
# tar xf x86_64-anywhere-linux-gnu-v5.tar.xz
# source ./x86_64-anywhere-linux-gnu/scripts/anywhere-setup.sh

# Configuration variables
# Define the environent STATIC_ENFORCE
STATIC_TOOLCHAIN=/home/vagrant #/usr/local/toolchain
STATIC_CHECKOUT=/vagrant #/usr/local/osquery
PREBUILT_FLAGS="-fPIC -DNDEBUG -march=x86-64 -Oz"
DARWIN_BUILD=10.13

# Relative paths
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SOURCE_DIR="$( realpath "${SCRIPT_DIR}/.." )"
THIRD_PARTY_BASE="${SOURCE_DIR}/third-party-prebuilt"

if [ -n ${ENFORCE_STATIC} ]; then
  if [ ! "${SOURCE_DIR}" = "${STATIC_CHECKOUT}" ]; then
    echo "To build prebuilts reproducably you must checkout osquery to ${STATIC_CHECKOUT}"
    false
  fi
fi

function exists() {
  TOOL=$1
  if ! hash $TOOL 2>/dev/null; then
    echo "Please install $TOOL"
    false
  fi
}

# Required tools
exists automake
exists pkg-config
exists libtoolize
exists autopoint
exists autoreconf
exists makeinfo # texinfo
exists yacc # bison bison.yacc
exists flex
exists xsltproc
exists cmake

# Platform specific configuration
if [ "$(uname)" == "Darwin" ]; then
  PLATFORM=Darwin
  PLATFORM_FLAGS="-mmacosx-version-min=${DARWIN_BUILD}"
	PLATFORM_LDFLAGS="-mmacosx-version-min=${DARWIN_BUILD}"
  PLATFORM_PATH="macos-x86_64"
elif [ "$(expr substr $(uname -s) 1 5)" == "Linux" ]; then
  PLATFORM=Linux
  PLATFORM_PATH="linux-x86_64"

  # Enforce static location of toolchain and checkout
  CC_PATH="$(which ${CC})"
  if [ -n ${ENFORCE_STATIC} ]; then
    if [ ! "${CC_PATH}" = "${STATIC_TOOLCHAIN}/x86_64-anywhere-linux-gnu/x86_64-anywhere-linux-gnu/sysroot/usr/bin/${CC}" ]; then
      echo "To build prebuilts reproducably you must install an x86_64 toolchain to ${STATIC_TOOLCHAIN}"
      false
    fi
  fi
fi

THIRD_PARTY_PREFIX="${THIRD_PARTY_BASE}/${PLATFORM_PATH}"

# Environment control
export CC=clang CXX=clang++
export SOURCE_DATE_EPOCH="0"
export ACLOCAL_PATH="${THIRD_PARTY_PREFIX}/share/aclocal:${ACLOCAL_PATH}"
export PKG_CONFIG_PATH="${THIRD_PARTY_PREFIX}/lib/pkgconfig:${PKG_CONFIG_PATH}"
export LDFLAGS="-L${THIRD_PARTY_PREFIX}/lib ${LDFLAGS} ${PLATFORM_LDFLAGS}"
export CPATH="${THIRD_PARTY_PREFIX}/include:${CPATH}"
export CFLAGS="-I${THIRD_PARTY_PREFIX}/include ${CFLAGS} ${PLATFORM_FLAGS} ${PREBUILT_FLAGS}"
export CXXFLAGS="-I${THIRD_PARTY_PREFIX}/include ${CXXFLAGS} ${DISTRO_FLAGS} ${PREBUILT_FLAGS}"
export PREFIX=${THIRD_PARTY_PREFIX}

BUILD_DIR="${SOURCE_DIR}/build/deps" # prebuilt

# If working in vagrant then the shared folder does not work
if [ "${PLATFORM}" = "Linux" ]; then
  FS_TYPE=$(stat --file-system --format=%T ${SOURCE_DIR} 2>&1)
fi

if [ "${FS_TYPE}" = "nfs" ]; then
  mkdir -p ~/deps
  ln -sf ~/deps "${SOURCE_DIR}/build"
else
  mkdir -p "${BUILD_DIR}"
fi

# CMake enforces these exist
mkdir -p "${THIRD_PARTY_PREFIX}/include"
mkdir -p "${THIRD_PARTY_PREFIX}/lib"

if [ "${LEGACY_BUILD}" = "1" ]; then
  make newdeps "${@}"
else
  ( cd "${BUILD_DIR}" && cmake "${SOURCE_DIR}" )
  ( cd "${BUILD_DIR}" && make thirdparty_prebuilt "${@}" )
fi

# Create reproducible archives
( cd "${THIRD_PARTY_PREFIX}/lib" && chmod -R +w * )
for f in "${THIRD_PARTY_PREFIX}/lib/"*.a; do objcopy -D $f &>/dev/null; done
for f in "${THIRD_PARTY_PREFIX}/lib/"*.a; do objcopy -D $f; done
