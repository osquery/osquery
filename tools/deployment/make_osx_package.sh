#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed in accordance with the terms specified in
#  the LICENSE file found in the root directory of this source tree.

set -e

# Defaults:
#   Set OSQUERY_BUILD_VERSION or add -v VERSION
#   Set BUILD_DIR or add -b DIR

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SOURCE_DIR="$SCRIPT_DIR/../.."
BUILD_DIR=${BUILD_DIR:="$SOURCE_DIR/build"}

source "$SOURCE_DIR/tools/lib.sh"

# Binary identifiers
VERSION=`(cd $SOURCE_DIR; git describe --tags HEAD) || echo 'unknown-version'`
APP_VERSION=${OSQUERY_BUILD_VERSION:="$VERSION"}

APP_IDENTIFIER="com.facebook.osquery"
LD_IDENTIFIER="com.facebook.osqueryd"
LD_INSTALL="/Library/LaunchDaemons/$LD_IDENTIFIER.plist"
SIGNING_IDENTITY=""
SIGNING_IDENTITY_COMMAND=""
KEYCHAIN_IDENTITY=""
KEYCHAIN_IDENTITY_COMMAND=""
AUTOSTART=false
CLEAN=false

# Config files
LAUNCHD_SRC="$SCRIPT_DIR/$LD_IDENTIFIER.plist"
LAUNCHD_DST="/private/var/osquery/$LD_IDENTIFIER.plist"
NEWSYSLOG_SRC="$SCRIPT_DIR/$LD_IDENTIFIER.conf"
NEWSYSLOG_DST="/private/var/osquery/$LD_IDENTIFIER.conf"
PACKS_SRC="$SOURCE_DIR/packs"
PACKS_DST="/private/var/osquery/packs/"
LENSES_LICENSE="libs/fb/augeas/augeas/1.9.0/COPYING"
LENSES_SRC="libs/fb/augeas/augeas/1.9.0/share/augeas/lenses/dist"
LENSES_DST="/private/var/osquery/lenses/"
OSQUERY_EXAMPLE_CONFIG_SRC="$SCRIPT_DIR/osquery.example.conf"
OSQUERY_EXAMPLE_CONFIG_DST="/private/var/osquery/osquery.example.conf"
OSQUERY_CONFIG_SRC=""
OSQUERY_CONFIG_DST="/private/var/osquery/osquery.conf"
OSQUERY_DB_LOCATION="/private/var/osquery/osquery.db/"
OSQUERY_LOG_DIR="/private/var/log/osquery/"
OSQUERY_TLS_CERT_CHAIN_BUILTIN_SRC="${SCRIPT_DIR}/certs.pem"
OSQUERY_TLS_CERT_CHAIN_BUILTIN_DST="/private/var/osquery/certs/certs.pem"
TLS_CERT_CHAIN_DST="/private/var/osquery/tls-server-certs.pem"
FLAGFILE_DST="/private/var/osquery/osquery.flags"
OSQUERY_PKG_INCLUDE_DIRS=()
OSQUERYCTL_PATH="$SCRIPT_DIR/osqueryctl"

SCRIPT_PREFIX_TEXT="#!/usr/bin/env bash

set -e
"

POSTINSTALL_UNLOAD_TEXT="
if launchctl list | grep -qcm1 $LD_IDENTIFIER; then
  launchctl unload $LD_INSTALL
fi
"

POSTINSTALL_AUTOSTART_TEXT="
cp $LAUNCHD_DST $LD_INSTALL
touch $FLAGFILE_DST
launchctl load $LD_INSTALL
"

POSTINSTALL_CLEAN_TEXT="
rm -rf $OSQUERY_DB_LOCATION
"

function usage() {
  fatal "Usage: $0
    [-b|--build] /path/to/build/dir
    [-c|--config] PATH embed an osqueryd config.
    [-l|--launchd] PATH override the default launchd plist.
    [-t|--cert-chain] PATH to embed a certificate chain file for TLS server validation
    [-o|--output] PATH override the output path.
    [-a|--autostart] start the daemon when the package is installed
    [-x|--clean] force the daemon to start fresh, removing any results previously stored in the database

  This will generate an macOS package with:
    (1) An example config /var/osquery/osquery.example.config
    (2) An optional config /var/osquery/osquery.config if [-c] is used
    (3) A LaunchDaemon plist /var/osquery/com.facebook.osqueryd.plist
    (4) A default TLS certificate bundle (provided by cURL)
    (5) The osquery toolset /usr/local/bin/osquery*

  To enable osqueryd to run at boot using Launchd, pass the -a flag.
  If the LaunchDaemon was previously installed a newer version of this package
  will reload (unload/load) the daemon."
}

function check_parsed_args() {
  if [[ ! -d $BUILD_DIR ]]; then
    fatal "Cannot find build dir [-b|--builddir]: $BUILD_DIR"
  fi

  if [[ ! -z $OSQUERY_CONFIG_SRC ]]; then
    log "using $OSQUERY_CONFIG_SRC as the config source"
  fi

  log "using $LAUNCHD_SRC as the launchd source"

  if [[ ! -z "$OSQUERY_CONFIG_SRC" ]] && [[ ! -f $OSQUERY_CONFIG_SRC ]]; then
    log "The config [-c] $OSQUERY_CONFIG_SRC is not a file"
    usage
  fi
}

function parse_args() {
  while [ "$1" != "" ]; do
    case $1 in
      -b | --build )          shift
                              BUILD_DIR=$1
                              ;;
      -v | --version )        shift
                              APP_VERSION=$1
                              ;;
      -c | --config )         shift
                              OSQUERY_CONFIG_SRC=$1
                              ;;
      -l | --launchd )        shift
                              LAUNCHD_SRC=$1
                              ;;
      -t | --cert-chain )     shift
                              TLS_CERT_CHAIN_SRC=$1
                              ;;
      -i | --include-dir )    shift
                              OSQUERY_PKG_INCLUDE_DIRS[${#OSQUERY_PKG_INCLUDE_DIRS}]=$1
                              ;;
      -o | --output )         shift
                              OUTPUT_PKG_PATH=$1
                              ;;
      -s | --sign )           shift
                              SIGNING_IDENTITY=$1
                              SIGNING_IDENTITY_COMMAND="--sign "$1
                              ;;
      -k | --keychain )       shift
                              KEYCHAIN_IDENTITY=$1
                              KEYCHAIN_IDENTITY_COMMAND="--keychain "$1
                              ;;
      -a | --autostart )      AUTOSTART=true
                              ;;
      -x | --clean )          CLEAN=true
                              ;;
      -h | --help )           usage
                              ;;
      * )                     usage
    esac
    shift
  done

  check_parsed_args
}

function main() {
  parse_args $@

  WORKING_DIR=$BUILD_DIR/_packaging
  INSTALL_PREFIX="$WORKING_DIR/prefix"
  DEBUG_PREFIX="$WORKING_DIR/debug"
  SCRIPT_ROOT="$WORKING_DIR/scripts"
  PREINSTALL="$SCRIPT_ROOT/preinstall"
  POSTINSTALL="$SCRIPT_ROOT/postinstall"

  platform OS
  if [[ ! "$OS" = "darwin" ]]; then
    fatal "This script must be run on macOS"
  fi

  OUTPUT_PKG_PATH="$BUILD_DIR/osquery-$APP_VERSION.pkg"
  OUTPUT_DEBUG_PKG_PATH="$BUILD_DIR/osquery-debug-$APP_VERSION.pkg"

  rm -rf $WORKING_DIR
  rm -f $OUTPUT_PKG_PATH
  mkdir -p $INSTALL_PREFIX
  mkdir -p $SCRIPT_ROOT

  # We don't need the preinstall for anything so let's skip it until we do
  # echo "$SCRIPT_PREFIX_TEXT" > $PREINSTALL
  # chmod +x $PREINSTALL

  log "copying osquery binaries into $INSTALL_PREFIX"
  BINARY_INSTALL_DIR="$INSTALL_PREFIX/usr/local/bin/"
  mkdir -p $BINARY_INSTALL_DIR
  cp "$BUILD_DIR/osquery/osqueryd" $BINARY_INSTALL_DIR
  ln -s osqueryd $BINARY_INSTALL_DIR/osqueryi
  strip $BINARY_INSTALL_DIR/*
  cp "$OSQUERYCTL_PATH" $BINARY_INSTALL_DIR

  if [[ ! "$SIGNING_IDENTITY" = "" ]]; then
    log "signing release binaries"
    codesign -s $SIGNING_IDENTITY --keychain \"$KEYCHAIN_IDENTITY\" $BINARY_INSTALL_DIR/osqueryd
  fi

  BINARY_DEBUG_DIR="$DEBUG_PREFIX/private/var/osquery/debug"
  mkdir -p "$BINARY_DEBUG_DIR"
  cp "$BUILD_DIR/osquery/osqueryd" $BINARY_DEBUG_DIR/osqueryd.debug
  ln -s osqueryd.debug $BINARY_DEBUG_DIR/osqueryi.debug

  # Create the prefix log dir and copy source configs.
  mkdir -p $INSTALL_PREFIX/$OSQUERY_LOG_DIR
  mkdir -p `dirname $INSTALL_PREFIX$OSQUERY_CONFIG_DST`
  if [[ "$OSQUERY_CONFIG_SRC" != "" ]]; then
    cp $OSQUERY_CONFIG_SRC $INSTALL_PREFIX$OSQUERY_CONFIG_DST
  fi

  # Move configurations into the packaging root.
  log "copying osquery configurations"
  mkdir -p `dirname $INSTALL_PREFIX$LAUNCHD_DST`
  mkdir -p $INSTALL_PREFIX$PACKS_DST
  mkdir -p $INSTALL_PREFIX$LENSES_DST
  cp $LAUNCHD_SRC $INSTALL_PREFIX$LAUNCHD_DST
  cp $NEWSYSLOG_SRC $INSTALL_PREFIX$NEWSYSLOG_DST
  cp $OSQUERY_EXAMPLE_CONFIG_SRC $INSTALL_PREFIX$OSQUERY_EXAMPLE_CONFIG_DST
  cp $PACKS_SRC/* $INSTALL_PREFIX$PACKS_DST
  cp $BUILD_DIR/$LENSES_LICENSE $INSTALL_PREFIX/$LENSES_DST
  cp $BUILD_DIR/$LENSES_SRC/*.aug $INSTALL_PREFIX$LENSES_DST
  if [[ "$TLS_CERT_CHAIN_SRC" != "" && -f "$TLS_CERT_CHAIN_SRC" ]]; then
    cp $TLS_CERT_CHAIN_SRC $INSTALL_PREFIX$TLS_CERT_CHAIN_DST
  fi

  if [[ $OSQUERY_TLS_CERT_CHAIN_BUILTIN_SRC != "" ]] && [[ -f $OSQUERY_TLS_CERT_CHAIN_BUILTIN_SRC ]]; then
    mkdir -p `dirname $INSTALL_PREFIX/$OSQUERY_TLS_CERT_CHAIN_BUILTIN_DST`
    cp $OSQUERY_TLS_CERT_CHAIN_BUILTIN_SRC $INSTALL_PREFIX/$OSQUERY_TLS_CERT_CHAIN_BUILTIN_DST
  fi

  # Move/install pre/post install scripts within the packaging root.
  log "finalizing preinstall and postinstall scripts"
  if [ $AUTOSTART == true ]  || [ $CLEAN == true ]; then
    echo "$SCRIPT_PREFIX_TEXT" > $POSTINSTALL
    chmod +x $POSTINSTALL
    if [ $CLEAN == true ]; then
        echo "$POSTINSTALL_CLEAN_TEXT" >> $POSTINSTALL
    fi
    if [ $AUTOSTART == true ]; then
        echo "$POSTINSTALL_UNLOAD_TEXT" >> $POSTINSTALL
        echo "$POSTINSTALL_AUTOSTART_TEXT" >> $POSTINSTALL
    fi
  fi

  # Copy extra files to the install prefix so that they get packaged too.
  # NOTE: Files will be overwritten.
  for include_dir in ${OSQUERY_PKG_INCLUDE_DIRS[*]}; do
    log "adding $include_dir in the package prefix to be included in the package"
    cp -fR $include_dir/* $INSTALL_PREFIX/
  done
  if [[ ! "$SIGNING_IDENTITY" = "" ]]; then
    log "creating signed release package"
  else
    log "creating package"
  fi
  pkgbuild --root $INSTALL_PREFIX       \
           --scripts $SCRIPT_ROOT       \
           --identifier $APP_IDENTIFIER \
           --version $APP_VERSION       \
           $SIGNING_IDENTITY_COMMAND    \
           $KEYCHAIN_IDENTITY_COMMAND   \
           $OUTPUT_PKG_PATH 2>&1  1>/dev/null
  log "package created at $OUTPUT_PKG_PATH"

  log "creating debug package"
  pkgbuild --root $DEBUG_PREFIX               \
           --identifier $APP_IDENTIFIER.debug \
           --version $APP_VERSION             \
           $OUTPUT_DEBUG_PKG_PATH 2>&1  1>/dev/null
  log "package created at $OUTPUT_DEBUG_PKG_PATH"
}

main $@
