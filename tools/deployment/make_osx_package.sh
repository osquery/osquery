#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SOURCE_DIR="$SCRIPT_DIR/../.."
BUILD_DIR="$SOURCE_DIR/build/"
if [[ ! -z "$DEBUG" ]]; then
  BUILD_DIR="${BUILD_DIR}debug_"
fi

if [[ "$BUILD_VERSION" == "10.11" ]]; then
  BUILD_DIR="${BUILD_DIR}darwin"
else
  BUILD_DIR="${BUILD_DIR}darwin$BUILD_VERSION"
fi

export PATH="$PATH:/usr/local/bin"
source "$SOURCE_DIR/tools/lib.sh"
distro "darwin" BUILD_VERSION

# Binary identifiers
APP_VERSION=`git describe --tags HEAD`
APP_IDENTIFIER="com.facebook.osquery"
KERNEL_APP_IDENTIFIER="com.facebook.osquery.kernel"
LD_IDENTIFIER="com.facebook.osqueryd"
LD_INSTALL="/Library/LaunchDaemons/$LD_IDENTIFIER.plist"
OUTPUT_PKG_PATH="$BUILD_DIR/osquery-$APP_VERSION.pkg"
KERNEL_OUTPUT_PKG_PATH="$BUILD_DIR/osquery-kernel-${APP_VERSION}.pkg"
AUTOSTART=false
CLEAN=false

# Config files
LAUNCHD_SRC="$SCRIPT_DIR/$LD_IDENTIFIER.plist"
LAUNCHD_DST="/private/var/osquery/$LD_IDENTIFIER.plist"
NEWSYSLOG_SRC="$SCRIPT_DIR/$LD_IDENTIFIER.conf"
NEWSYSLOG_DST="/private/var/osquery/$LD_IDENTIFIER.conf"
PACKS_SRC="$SOURCE_DIR/packs"
PACKS_DST="/private/var/osquery/packs/"
LENSES_LICENSE="/usr/local/osquery/Cellar/augeas/*/COPYING"
LENSES_SRC="/usr/local/osquery/share/augeas/lenses/dist"
LENSES_DST="/private/var/osquery/lenses/"
OSQUERY_EXAMPLE_CONFIG_SRC="$SCRIPT_DIR/osquery.example.conf"
OSQUERY_EXAMPLE_CONFIG_DST="/private/var/osquery/osquery.example.conf"
OSQUERY_CONFIG_SRC=""
OSQUERY_CONFIG_DST="/private/var/osquery/osquery.conf"
OSQUERY_DB_LOCATION="/private/var/osquery/osquery.db/"
OSQUERY_LOG_DIR="/private/var/log/osquery/"
OSQUERY_TLS_CERT_CHAIN_BUILTIN_SRC="/usr/local/osquery/etc/openssl/cert.pem"
OSQUERY_TLS_CERT_CHAIN_BUILTIN_DST="/private/var/osquery/certs/certs.pem"
TLS_CERT_CHAIN_DST="/private/var/osquery/tls-server-certs.pem"
FLAGFILE_DST="/private/var/osquery/osquery.flags"

WORKING_DIR=/tmp/osquery_packaging
INSTALL_PREFIX="$WORKING_DIR/prefix"
SCRIPT_ROOT="$WORKING_DIR/scripts"
PREINSTALL="$SCRIPT_ROOT/preinstall"
POSTINSTALL="$SCRIPT_ROOT/postinstall"
OSQUERYCTL_PATH="$SCRIPT_DIR/osqueryctl"

# Kernel extension identifiers and config files
KERNEL_INLINE=false
KERNEL_UNLOAD_SCRIPT="$SOURCE_DIR/kernel/tools/unload_with_retry.sh"
KERNEL_EXTENSION_IDENTIFIER="com.facebook.security.osquery"
KERNEL_EXTENSION_SRC="$BUILD_DIR/kernel/osquery.kext"
KERNEL_EXTENSION_DST="/Library/Extensions/osquery.kext"

KERNEL_WORKING_DIR=/tmp/osquery_kernel_packaging
KERNEL_INSTALL_PREFIX="$KERNEL_WORKING_DIR/prefix"
KERNEL_SCRIPT_ROOT="$KERNEL_WORKING_DIR/scripts"
KERNEL_PREINSTALL="$KERNEL_SCRIPT_ROOT/preinstall"
KERNEL_POSTINSTALL="$KERNEL_SCRIPT_ROOT/postinstall"

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

KERNEL_POSTINSTALL_UNLOAD_TEXT="
./unload_with_retry.sh
"

KERNEL_POSTINSTALL_AUTOSTART_TEXT="
kextload $KERNEL_EXTENSION_DST
"

POSTINSTALL_CLEAN_TEXT="
rm -rf $OSQUERY_DB_LOCATION
"

function usage() {
  fatal "Usage: $0 [-c path/to/your/osquery.conf] [-l path/to/osqueryd.plist]
    -c PATH embed an osqueryd config.
    -l PATH override the default launchd plist.
    -t PATH to embed a certificate chain file for TLS server validation
    -o PATH override the output path.
    -a start the daemon when the package is installed
    -x force the daemon to start fresh, removing any results previously stored in the database
  This will generate an OSX package with:
  (1) An example config /var/osquery/osquery.example.config
  (2) An optional config /var/osquery/osquery.config if [-c] is used
  (3) A LaunchDaemon plist /var/osquery/com.facebook.osqueryd.plist
  (4) A default TLS certificate bundle (provided by cURL)
  (5) The osquery toolset /usr/local/bin/osquery*

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
      -t | --cert-chain )     shift
                              TLS_CERT_CHAIN_SRC=$1
                              ;;
      -o | --output )         shift
                              OUTPUT_PKG_PATH=$1
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
  cp $LENSES_LICENSE $INSTALL_PREFIX/$LENSES_DST
  cp $LENSES_SRC/*.aug $INSTALL_PREFIX$LENSES_DST
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

  log "creating package"
  pkgbuild --root $INSTALL_PREFIX       \
           --scripts $SCRIPT_ROOT       \
           --identifier $APP_IDENTIFIER \
           --version $APP_VERSION       \
           $OUTPUT_PKG_PATH 2>&1  1>/dev/null
  log "package created at $OUTPUT_PKG_PATH"

  # We optionally create an RPM equivalent.
  FPM=$(which fpm || true)
  RPMBUILD=$(which rpmbuild || true)
  if [[ ! "$FPM" = "" && ! "$RPMBUILD" = "" ]]; then
    rm -f "$OUTPUT_RPM_PATH"
    log "creating RPM equivalent"

    # Yes, RPMs on OS X like i386 as the arch.
    PACKAGE_ARCH=i386
    PACKAGE_ITERATION="1.darwin"
    RPM_APP_VERSION=$(echo ${APP_VERSION}|tr '-' '_')
    OUTPUT_RPM_PATH="$BUILD_DIR/osquery-$RPM_APP_VERSION-$PACKAGE_ITERATION.$PACKAGE_ARCH.rpm"
    CMD="$FPM -s dir -t rpm \
      -n osquery \
      -v $RPM_APP_VERSION \
      --iteration $PACKAGE_ITERATION -a $PACKAGE_ARCH \
      -p $OUTPUT_RPM_PATH \
      --url https://osquery.io -m osquery@osquery.io \
      --vendor Facebook --license BSD \
      \"$INSTALL_PREFIX/=/\""
    eval "$CMD"
    log "RPM package (also) created at $OUTPUT_RPM_PATH"
  else
    log "Skipping OS X RPM package build: Cannot find fpm and rpmbuild"
  fi

  # Check if a kernel extension should be built alongside.
  if [[ -d "$KERNEL_EXTENSION_SRC" ]]; then
    rm -rf $KERNEL_WORKING_DIR
    rm -f $KERNEL_OUTPUT_PKG_PATH
    mkdir -p $KERNEL_INSTALL_PREFIX
    mkdir -p $KERNEL_SCRIPT_ROOT

    log "copying osquery kernel bundles"
    mkdir -p $KERNEL_INSTALL_PREFIX$KERNEL_EXTENSION_DST
    cp -R $KERNEL_EXTENSION_SRC/ $KERNEL_INSTALL_PREFIX$KERNEL_EXTENSION_DST

    log "finalizing kernel preinstall and postinstall scripts"
    if [ $AUTOSTART == true ]; then
      echo "$SCRIPT_PREFIX_TEXT" > $KERNEL_POSTINSTALL
      chmod +x $KERNEL_POSTINSTALL
      # Install the normal post install unload to unload the daemons.
      echo "$POSTINSTALL_UNLOAD_TEXT" >> $KERNEL_POSTINSTALL
      # Handler kernel extension unloading/reloading.
      cp $KERNEL_UNLOAD_SCRIPT $KERNEL_SCRIPT_ROOT
      echo "$KERNEL_POSTINSTALL_UNLOAD_TEXT" >> $KERNEL_POSTINSTALL
      echo "$KERNEL_POSTINSTALL_AUTOSTART_TEXT" >> $KERNEL_POSTINSTALL
      # Install the normal post install reload to reload daemons.
      echo "$POSTINSTALL_AUTOSTART_TEXT" >> $KERNEL_POSTINSTALL
    fi

    log "creating kernel package"
    pkgbuild --root $KERNEL_INSTALL_PREFIX             \
             --scripts $KERNEL_SCRIPT_ROOT             \
             --identifier $KERNEL_APP_IDENTIFIER       \
             --version ${APP_VERSION}                  \
             $KERNEL_OUTPUT_PKG_PATH 2>&1  1>/dev/null
    log "kernel package created at $KERNEL_OUTPUT_PKG_PATH"
  else
    log "skipping kernel package, no kext found"
  fi

}

main $@
