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
BUILD_DIR="$SOURCE_DIR/build/darwin"
export PATH="$PATH:/usr/local/bin"

source $SCRIPT_DIR/../lib.sh

APP_VERSION=`git describe --tags HEAD`
APP_IDENTIFIER="com.facebook.osquery"
LD_IDENTIFIER="com.facebook.osqueryd"
OUTPUT_PKG_PATH="$SOURCE_DIR/osquery-$APP_VERSION.pkg"
LAUNCHD_PATH="$SCRIPT_DIR/$LD_IDENTIFIER.plist"
LAUNCHD_PATH_OVERRIDE=""
LAUNCHD_INSTALL_PATH="/Library/LaunchDaemons/$LD_IDENTIFIER.plist"
INCLUDE_LAUNCHD=true
SIMPLE_INSTALL=false
OSQUERY_LOG_DIR="/var/log/osquery/"
OSQUERY_CONFIG_PATH_DEST="/var/osquery/osquery.conf"
OSQUERY_CONFIG_PATH_SOURCE=""

BREW_PACKAGES=(rocksdb boost gflags glog thrift)
BREW_PREFIX=`brew --prefix`
BREW_CELLAR=`brew --cellar`

WORKING_DIR=/tmp/osquery_packaging
INSTALL_PREFIX=$WORKING_DIR/prefix
SCRIPT_ROOT=$WORKING_DIR/scripts
PREINSTALL=$SCRIPT_ROOT/preinstall
POSTINSTALL=$SCRIPT_ROOT/postinstall

SCRIPT_PREFIX_TEXT="#!/usr/bin/env bash

set -e
"

POSTINSTALL_ADDITIONAL_TEXT="
if launchctl list | grep -qcm1 osquery; then
  launchctl unload $LAUNCHD_INSTALL_PATH
fi

launchctl load $LAUNCHD_INSTALL_PATH
"

function usage() {
  fatal "Usage: $0 [-c path/to/your/osquery.conf] [-n] [-l path/to/osqueryd.plist]
    -c PATH embed an osqueryd config.
    -n Do not embed the default launchd entry.
    -l PATH override the default launchd entry."
}

function parse_args() {
  while [ "$1" != "" ]; do
    case $1 in
      -c | --config )         shift
                              OSQUERY_CONFIG_PATH_SRC=$1
                              ;;
      -l | --launchd-path )   shift
                              LAUNCHD_PATH_OVERRIDE=$1
                              ;;
      -n | --no-launchd )     INCLUDE_LAUNCHD=false
                              ;;
      -h | --help )           usage
                              ;;
      * )                     usage
    esac
    shift
  done
}

function check_parsed_args() {
  if [[ $OSQUERY_CONFIG_PATH_SRC = "" ]]; then
    log "no config specified. assuming that you know what you're doing."
  fi

  if [[ $INCLUDE_LAUNCHD = true ]]; then
    if [[ $LAUNCHD_PATH_OVERRIDE = "" ]]; then
      log "no custom launchd path was defined. using $LAUNCHD_PATH"
    else
      LAUNCHD_PATH=$LAUNCHD_PATH_OVERRIDE
      log "using $LAUNCHD_PATH as the launchd path"
    fi
  fi

  if [ "$OSQUERY_CONFIG_PATH_SRC" != "" ] && [ ! -f $OSQUERY_CONFIG_PATH_SRC ]; then
    log "$OSQUERY_CONFIG_PATH_SRC is not a file"
    usage
  fi
}

function main() {
  parse_args $@
  check_parsed_args

  platform OS
  if [[ ! "$OS" = "darwin" ]]; then
    fatal "This script must be ran on OS X"
  fi
  rm -rf $WORKING_DIR
  rm -f $OUTPUT_PKG_PATH
  mkdir -p $INSTALL_PREFIX
  mkdir -p $SCRIPT_ROOT
  # we don't need the preinstall for anything so let's skip it until we do
  # echo "$SCRIPT_PREFIX_TEXT" > $PREINSTALL
  # chmod +x $PREINSTALL

  echo "$SCRIPT_PREFIX_TEXT" > $POSTINSTALL
  chmod +x $POSTINSTALL

  log "copying osquery binaries"
  BINARY_INSTALL_DIR="$INSTALL_PREFIX/usr/local/bin/"
  mkdir -p $BINARY_INSTALL_DIR
  cp "$BUILD_DIR/osquery/osqueryi" $BINARY_INSTALL_DIR
  cp "$BUILD_DIR/osquery/osqueryd" $BINARY_INSTALL_DIR
  mkdir -p $INSTALL_PREFIX/$OSQUERY_LOG_DIR
  mkdir -p `dirname $INSTALL_PREFIX$OSQUERY_CONFIG_PATH_DEST`
  if [[ "$OSQUERY_CONFIG_PATH_SRC" != "" ]]; then
    cp $OSQUERY_CONFIG_PATH_SRC $INSTALL_PREFIX$OSQUERY_CONFIG_PATH_DEST
  fi

  log "copying osquery configurations"
  if [[ $INCLUDE_LAUNCHD = true ]]; then
    mkdir -p `dirname $INSTALL_PREFIX$LAUNCHD_INSTALL_PATH`
    cp $LAUNCHD_PATH $INSTALL_PREFIX$LAUNCHD_INSTALL_PATH
  else
    log "skipping LaunchDaemon file"
  fi

  log "finalizing preinstall and postinstall scripts"
  if [[ $INCLUDE_LAUNCHD = true ]]; then
    echo "$POSTINSTALL_ADDITIONAL_TEXT" >> $POSTINSTALL
  else
    log "skipping LaunchDaemon commands"
  fi

  log "creating package"
  pkgbuild --root $INSTALL_PREFIX       \
           --scripts $SCRIPT_ROOT       \
           --identifier $APP_IDENTIFIER \
           --version $APP_VERSION       \
           $OUTPUT_PKG_PATH 2>&1  1>/dev/null
  log "package created at $OUTPUT_PKG_PATH"
}

main $@
