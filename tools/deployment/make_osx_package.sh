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
LD_INSTALL="/Library/LaunchDaemons/$LD_IDENTIFIER.plist"
if [[ $APP_VERSION == *"-"* ]]; then
  APP_NAME="osquery-latest"
else
  APP_NAME="osquery"
fi
OUTPUT_PKG_PATH="$BUILD_DIR/$APP_NAME-$APP_VERSION.pkg"
AUTOSTART=false

# Config files
LAUNCHD_SRC="$SCRIPT_DIR/$LD_IDENTIFIER.plist"
LAUNCHD_DST="/var/osquery/$LD_IDENTIFIER.plist"
OSQUERY_EXAMPLE_CONFIG_SRC="$SCRIPT_DIR/osquery.example.conf"
OSQUERY_EXAMPLE_CONFIG_DST="/var/osquery/osquery.example.conf"
OSQUERY_CONFIG_SRC=""
OSQUERY_CONFIG_DST="/var/osquery/osquery.conf"
OSQUERY_LOG_DIR="/var/log/osquery/"

WORKING_DIR=/tmp/osquery_packaging
INSTALL_PREFIX=$WORKING_DIR/prefix
SCRIPT_ROOT=$WORKING_DIR/scripts
PREINSTALL=$SCRIPT_ROOT/preinstall
POSTINSTALL=$SCRIPT_ROOT/postinstall
OSQUERYCTL_PATH="$SOURCE_DIR/tools/deployment/osqueryctl"

SCRIPT_PREFIX_TEXT="#!/usr/bin/env bash

set -e
"

POSTINSTALL_AUTOSTART_TEXT="
if launchctl list | grep -qcm1 osquery; then
  launchctl unload $LD_INSTALL
fi
cp $LAUNCHD_DST $LD_INSTALL
launchctl load $LD_INSTALL
"

function usage() {
  fatal "Usage: $0 [-c path/to/your/osquery.conf] [-l path/to/osqueryd.plist]
    -c PATH embed an osqueryd config.
    -l PATH override the default launchd plist.
    -o PATH override the output path.
    -a start the daemon when the package is installed

  This will generate an OSX package with:
  (1) An example config /var/osquery/osquery.example.config
  (2) An optional config /var/osquery/osquery.config if [-c] is used
  (3) A LaunchDaemon plist /var/osquery/com.facebook.osqueryd.plist
  (4) The osquery toolset /usr/local/bin/osquery*

  To enable osqueryd to run at boot using Launchd, pass the -a flag.
  If the LaunchDaemon was previously installed a newer version of this package
  will reload (unload/load) the daemon."
}

function parse_args() {
  while [ "$1" != "" ]; do
    case $1 in
      -c | --config )         shift
                              OSQUERY_CONFIG_SRC=$1
                              ;;
      -l | --launchd )        shift
                              LAUNCHD_SRC=$1
                              ;;
      -o | --output )         shift
                              OUTPUT_PKG_PATH=$1
                              ;;
      -a | --autostart )      AUTOSTART=true
                              ;;
      -h | --help )           usage
                              ;;
      * )                     usage
    esac
    shift
  done
}

function check_parsed_args() {
  if [[ $OSQUERY_CONFIG_SRC = "" ]]; then
    log "notice: no config source specified"
  else
    log "using $OSQUERY_CONFIG_SRC as the config source"
  fi

  log "using $LAUNCHD_SRC as the launchd source"

  if [ "$OSQUERY_CONFIG_SRC" != "" ] && [ ! -f $OSQUERY_CONFIG_SRC ]; then
    log "$OSQUERY_CONFIG_SRC is not a file."
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


  log "copying osquery binaries"
  BINARY_INSTALL_DIR="$INSTALL_PREFIX/usr/local/bin/"
  mkdir -p $BINARY_INSTALL_DIR
  cp "$BUILD_DIR/osquery/osqueryi" $BINARY_INSTALL_DIR
  cp "$BUILD_DIR/osquery/osqueryd" $BINARY_INSTALL_DIR
  strip $BINARY_INSTALL_DIR/*
  cp "$OSQUERYCTL_PATH" $BINARY_INSTALL_DIR

  # Create the prefix log dir and copy source configs
  mkdir -p $INSTALL_PREFIX/$OSQUERY_LOG_DIR
  mkdir -p `dirname $INSTALL_PREFIX$OSQUERY_CONFIG_DST`
  if [[ "$OSQUERY_CONFIG_SRC" != "" ]]; then
    cp $OSQUERY_CONFIG_SRC $INSTALL_PREFIX$OSQUERY_CONFIG_DST
  fi

  log "copying osquery configurations"
  mkdir -p `dirname $INSTALL_PREFIX$LAUNCHD_DST`
  cp $LAUNCHD_SRC $INSTALL_PREFIX$LAUNCHD_DST
  cp $OSQUERY_EXAMPLE_CONFIG_SRC $INSTALL_PREFIX$OSQUERY_EXAMPLE_CONFIG_DST

  log "finalizing preinstall and postinstall scripts"
  if [ $AUTOSTART == true ]; then
    echo "$SCRIPT_PREFIX_TEXT" > $POSTINSTALL
    chmod +x $POSTINSTALL
    echo "$POSTINSTALL_AUTOSTART_TEXT" >> $POSTINSTALL
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
