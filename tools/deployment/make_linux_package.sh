#!/usr/bin/env bash

#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SOURCE_DIR="$SCRIPT_DIR/../.."
BUILD_DIR="$SOURCE_DIR/build/linux"
export PATH="$PATH:/usr/local/bin"

source $SCRIPT_DIR/../lib.sh

PACKAGE_VERSION=`git describe --tags HEAD || echo 'unknown-version'`
PACKAGE_ARCH=`uname -m`
PACKAGE_ITERATION=""
PACKAGE_TYPE=""
DESCRIPTION="osquery is an operating system instrumentation toolchain."
PACKAGE_NAME="osquery"
if [[ $PACKAGE_VERSION == *"-"* ]]; then
  DESCRIPTION="$DESCRIPTION (unstable/latest version)"
fi
OUTPUT_PKG_PATH="$BUILD_DIR/$PACKAGE_NAME-$PACKAGE_VERSION."

# Config files
INITD_SRC="$SCRIPT_DIR/osqueryd.initd"
INITD_DST="/etc/init.d/osqueryd"
SYSTEMD_SERVICE_SRC="$SCRIPT_DIR/osqueryd.service"
SYSTEMD_SERVICE_DST="/usr/lib/systemd/system/osqueryd.service"
SYSTEMD_SYSCONFIG_SRC="$SCRIPT_DIR/osqueryd.sysconfig"
SYSTEMD_SYSCONFIG_DST="/etc/sysconfig/osqueryd"
CTL_SRC="$SCRIPT_DIR/osqueryctl"
PACKS_SRC="$SOURCE_DIR/packs"
PACKS_DST="/usr/share/osquery/packs/"
OSQUERY_EXAMPLE_CONFIG_SRC="$SCRIPT_DIR/osquery.example.conf"
OSQUERY_EXAMPLE_CONFIG_DST="/usr/share/osquery/osquery.example.conf"
OSQUERY_LOG_DIR="/var/log/osquery/"
OSQUERY_VAR_DIR="/var/osquery"
OSQUERY_ETC_DIR="/etc/osquery"

WORKING_DIR=/tmp/osquery_packaging
INSTALL_PREFIX=$WORKING_DIR/prefix

function usage() {
  fatal "Usage: $0 -t deb|rpm -i REVISION -d DEPENDENCY_LIST

  This will generate an Linux package with:
  (1) An example config /var/osquery/osquery.example.config
  (2) An init.d script /etc/init.d/osqueryd
  (3) The osquery toolset /usr/bin/osquery*"
}

function parse_args() {
  while [ "$1" != "" ]; do
    case $1 in
      -t | --type )           shift
                              PACKAGE_TYPE=$1
                              ;;
      -i | --iteration )      shift
                              PACKAGE_ITERATION=$1
                              ;;
      -d | --dependencies )   shift
                              PACKAGE_DEPENDENCIES="${@}"
                              ;;
      -h | --help )           usage
                              ;;
    esac
    shift
  done
}

function check_parsed_args() {
  if [[ $PACKAGE_TYPE = "" ]] || [[ $PACKAGE_ITERATION = "" ]]; then
    usage
  fi

  OUTPUT_PKG_PATH=$OUTPUT_PKG_PATH$PACKAGE_TYPE
}

function main() {
  parse_args $@
  check_parsed_args

  platform OS
  distro $OS DISTRO

  rm -rf $WORKING_DIR
  rm -f $OUTPUT_PKG_PATH
  mkdir -p $INSTALL_PREFIX

  log "copying osquery binaries"
  BINARY_INSTALL_DIR="$INSTALL_PREFIX/usr/bin/"
  mkdir -p $BINARY_INSTALL_DIR
  cp "$BUILD_DIR/osquery/osqueryi" $BINARY_INSTALL_DIR
  cp "$BUILD_DIR/osquery/osqueryd" $BINARY_INSTALL_DIR
  strip $BINARY_INSTALL_DIR/*
  cp "$CTL_SRC" $BINARY_INSTALL_DIR

  # Create the prefix log dir and copy source configs
  log "copying osquery configurations"
  mkdir -p $INSTALL_PREFIX/$OSQUERY_VAR_DIR
  mkdir -p $INSTALL_PREFIX/$OSQUERY_LOG_DIR
  mkdir -p $INSTALL_PREFIX/$OSQUERY_ETC_DIR
  mkdir -p $INSTALL_PREFIX/$PACKS_DST
  mkdir -p `dirname $INSTALL_PREFIX$OSQUERY_EXAMPLE_CONFIG_DST`
  cp $OSQUERY_EXAMPLE_CONFIG_SRC $INSTALL_PREFIX$OSQUERY_EXAMPLE_CONFIG_DST
  cp $PACKS_SRC/* $INSTALL_PREFIX/$PACKS_DST

  if [[ $DISTRO = "centos7" || $DISTRO = "rhel7" ]]; then
    # Install the systemd service and sysconfig
    mkdir -p `dirname $INSTALL_PREFIX$SYSTEMD_SERVICE_DST`
    mkdir -p `dirname $INSTALL_PREFIX$SYSTEMD_SYSCONFIG_DST`
    cp $SYSTEMD_SERVICE_SRC $INSTALL_PREFIX$SYSTEMD_SERVICE_DST
    cp $SYSTEMD_SYSCONFIG_SRC $INSTALL_PREFIX$SYSTEMD_SYSCONFIG_DST
  else
    mkdir -p `dirname $INSTALL_PREFIX$INITD_DST`
    cp $INITD_SRC $INSTALL_PREFIX$INITD_DST
  fi

  log "creating package"
  IFS=',' read -a deps <<< "$PACKAGE_DEPENDENCIES"
  PACKAGE_DEPENDENCIES=
  for element in "${deps[@]}"
  do
    element=`echo $element | sed 's/ *$//'`
    PACKAGE_DEPENDENCIES="$PACKAGE_DEPENDENCIES -d \"$element\""
  done

  platform OS
  distro $OS DISTRO
  FPM="fpm"
  if [[ $DISTRO == "lucid" ]]; then
    FPM="/var/lib/gems/1.8/bin/fpm"
  fi

  CMD="$FPM -s dir -t $PACKAGE_TYPE \
    -n $PACKAGE_NAME -v $PACKAGE_VERSION \
    --iteration $PACKAGE_ITERATION \
    -a $PACKAGE_ARCH               \
    $PACKAGE_DEPENDENCIES          \
    -p $OUTPUT_PKG_PATH            \
    --url https://osquery.io       \
    -m osquery@osquery.io          \
    --vendor Facebook              \
    --license BSD                  \
    --description \"$DESCRIPTION\" \
    \"$INSTALL_PREFIX/=/\""
  eval "$CMD"
  log "package created at $OUTPUT_PKG_PATH"
}

main $@
