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
BUILD_DIR=${BUILD_DIR:="$SOURCE_DIR/build/linux"}

OSQUERY_DEPS="${OSQUERY_DEPS:-/usr/local/osquery}"

export PATH="${OSQUERY_DEPS}/bin:$PATH"
source "$SOURCE_DIR/tools/lib.sh"

PACKAGE_VERSION=`git describe --tags HEAD || echo 'unknown-version'`
PACKAGE_ARCH="x86_64"
PACKAGE_TYPE=""
PACKAGE_ITERATION=""
DESCRIPTION="osquery is an operating system instrumentation toolchain."
PACKAGE_NAME="osquery"
if [[ $PACKAGE_VERSION == *"-"* ]]; then
  DESCRIPTION="$DESCRIPTION (unstable/latest version)"
fi

# Config files
INITD_SRC="$SCRIPT_DIR/osqueryd.initd"
INITD_DST="/etc/init.d/osqueryd"
SYSTEMD_SERVICE_SRC="$SCRIPT_DIR/osqueryd.service"
SYSTEMD_SERVICE_DST="/usr/lib/systemd/system/osqueryd.service"
SYSTEMD_SYSCONFIG_SRC="$SCRIPT_DIR/osqueryd.sysconfig"
SYSTEMD_SYSCONFIG_DST="/etc/sysconfig/osqueryd"
SYSTEMD_SYSCONFIG_DST_DEB="/etc/default/osqueryd"
CTL_SRC="$SCRIPT_DIR/osqueryctl"
PACKS_SRC="$SOURCE_DIR/packs"
PACKS_DST="/usr/share/osquery/packs/"
LENSES_LICENSE="${OSQUERY_DEPS}/Cellar/augeas/*/COPYING"
LENSES_SRC="${OSQUERY_DEPS}/share/augeas/lenses/dist"
LENSES_DST="/usr/share/osquery/lenses/"
OSQUERY_POSTINSTALL=${OSQUERY_POSTINSTALL:-""}
OSQUERY_PREUNINSTALL=${OSQUERY_PREUNINSTALL:-""}
OSQUERY_CONFIG_SRC=${OSQUERY_CONFIG_SRC:-""}
OSQUERY_TLS_CERT_CHAIN_SRC=${OSQUERY_TLS_CERT_CHAIN_SRC:-""}
OSQUERY_TLS_CERT_CHAIN_BUILTIN_SRC="${OSQUERY_DEPS}/etc/openssl/cert.pem"
OSQUERY_TLS_CERT_CHAIN_BUILTIN_DST="/usr/share/osquery/certs/certs.pem"
OSQUERY_EXAMPLE_CONFIG_SRC="$SCRIPT_DIR/osquery.example.conf"
OSQUERY_EXAMPLE_CONFIG_DST="/usr/share/osquery/osquery.example.conf"
OSQUERY_LOG_DIR="/var/log/osquery/"
OSQUERY_VAR_DIR="/var/osquery"
OSQUERY_ETC_DIR="/etc/osquery"

WORKING_DIR=/tmp/osquery_packaging
INSTALL_PREFIX=$WORKING_DIR/prefix
DEBUG_PREFIX=$WORKING_DIR/debug

function usage() {
  fatal "Usage: $0 -t deb|rpm -i REVISION -d DEPENDENCY_LIST
    [-u|--preuninst] /path/to/pre-uninstall
    [-p|--postinst] /path/to/post-install
    [-c|--config] /path/to/embedded.config
  This will generate an Linux package with:
  (1) An example config /usr/share/osquery/osquery.example.conf
  (2) An init.d script /etc/init.d/osqueryd
  (3) A systemd service file /usr/lib/systemd/system/osqueryd.service and
      a sysconfig file /etc/{default|sysconfig}/osqueryd as appropriate
  (4) A default TLS certificate bundle (provided by cURL)
  (5) The osquery toolset /usr/bin/osquery*"
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
      -u | --preuninst)       shift
                              OSQUERY_PREUNINSTALL=$1
                              ;;
      -p | --postinst )       shift
                              OSQUERY_POSTINSTALL=$1
                              ;;
      -c | --config )         shift
                              OSQUERY_CONFIG_SRC=$1
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
}

function get_pkg_suffix() {
  if [[ $PACKAGE_TYPE == "deb" ]]; then
    # stay compliant with Debian package naming convention
    echo "_${PACKAGE_VERSION}_${PACKAGE_ITERATION}.amd64.${PACKAGE_TYPE}"
  elif [[ $PACKAGE_TYPE == "rpm" ]]; then
    V=`echo ${PACKAGE_VERSION}|tr '-' '_'`
    echo "-${V}-${PACKAGE_ITERATION}.${PACKAGE_ARCH}.${PACKAGE_TYPE}"
  elif [[ $PACKAGE_TYPE == "pacman" ]]; then
    echo "-${PACKAGE_VERSION}-${PACKAGE_ITERATION}-${PACKAGE_ARCH}.pkg.tar.xz"
  else
    echo "-${PACKAGE_VERSION}_${PACKAGE_ITERATION}_${PACKAGE_ARCH}.tar.gz"
  fi
}

function main() {
  parse_args $@
  check_parsed_args

  platform OS
  distro $OS DISTRO

  OUTPUT_PKG_PATH=`realpath "$BUILD_DIR"`/$PACKAGE_NAME$(get_pkg_suffix)

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
  mkdir -p $INSTALL_PREFIX/$LENSES_DST
  mkdir -p `dirname $INSTALL_PREFIX$OSQUERY_EXAMPLE_CONFIG_DST`
  cp $OSQUERY_EXAMPLE_CONFIG_SRC $INSTALL_PREFIX$OSQUERY_EXAMPLE_CONFIG_DST
  cp $PACKS_SRC/* $INSTALL_PREFIX/$PACKS_DST
  cp $LENSES_LICENSE $INSTALL_PREFIX/$LENSES_DST
  cp $LENSES_SRC/*.aug $INSTALL_PREFIX/$LENSES_DST

  if [[ $OSQUERY_CONFIG_SRC != "" ]] && [[ -f $OSQUERY_CONFIG_SRC ]]; then
    log "config setup"
    cp $OSQUERY_CONFIG_SRC $INSTALL_PREFIX/$OSQUERY_ETC_DIR/osquery.conf
  fi

  if [[ $OSQUERY_TLS_CERT_CHAIN_SRC != "" ]] && [[ -f $OSQUERY_TLS_CERT_CHAIN_SRC ]]; then
    log "custom tls server certs file setup"
    cp $OSQUERY_TLS_CERT_CHAIN_SRC $INSTALL_PREFIX/$OSQUERY_ETC_DIR/tls-server-certs.pem
  fi

  if [[ $OSQUERY_TLS_CERT_CHAIN_BUILTIN_SRC != "" ]] && [[ -f $OSQUERY_TLS_CERT_CHAIN_BUILTIN_SRC ]]; then
    log "built-in tls server certs file setup"
    mkdir -p `dirname $INSTALL_PREFIX/$OSQUERY_TLS_CERT_CHAIN_BUILTIN_DST`
    cp $OSQUERY_TLS_CERT_CHAIN_BUILTIN_SRC $INSTALL_PREFIX/$OSQUERY_TLS_CERT_CHAIN_BUILTIN_DST
  fi

  if [[ $PACKAGE_TYPE = "deb" ]]; then
    #Change config path to Ubuntu default
    SYSTEMD_SYSCONFIG_DST=$SYSTEMD_SYSCONFIG_DST_DEB
  fi

  log "copying osquery init scripts"
  mkdir -p `dirname $INSTALL_PREFIX$INITD_DST`
  mkdir -p `dirname $INSTALL_PREFIX$SYSTEMD_SERVICE_DST`
  mkdir -p `dirname $INSTALL_PREFIX$SYSTEMD_SYSCONFIG_DST`
  cp $INITD_SRC $INSTALL_PREFIX$INITD_DST
  cp $SYSTEMD_SERVICE_SRC $INSTALL_PREFIX$SYSTEMD_SERVICE_DST
  cp $SYSTEMD_SYSCONFIG_SRC $INSTALL_PREFIX$SYSTEMD_SYSCONFIG_DST

  if [[ $PACKAGE_TYPE = "deb" ]]; then
    #Change config path in service unit
    sed -i 's/sysconfig/default/g' $INSTALL_PREFIX$SYSTEMD_SERVICE_DST
  fi

  log "creating $PACKAGE_TYPE package"
  IFS=',' read -a deps <<< "$PACKAGE_DEPENDENCIES"
  PACKAGE_DEPENDENCIES=
  for element in "${deps[@]}"
  do
    element=`echo $element | sed 's/ *$//'`
    PACKAGE_DEPENDENCIES="$PACKAGE_DEPENDENCIES -d \"$element\""
  done

  # Let callers provide their own fpm if desired
  FPM=${FPM:="fpm"}

  POSTINST_CMD=""
  if [[ $OSQUERY_POSTINSTALL != "" ]] && [[ -f $OSQUERY_POSTINSTALL ]]; then
    POSTINST_CMD="--after-install $OSQUERY_POSTINSTALL"
  fi

  PREUNINST_CMD=""
  if [[ $OSQUERY_PREUNINSTALL != "" ]] && [[ -f $OSQUERY_PREUNINSTALL ]]; then
    PREUNINST_CMD="--before-remove $OSQUERY_PREUNINSTALL"
  fi

  # Change directory modes
  find $INSTALL_PREFIX/ -type d | xargs chmod 755

  EPILOG="--url https://osquery.io \
    -m osquery@osquery.io          \
    --vendor Facebook              \
    --license BSD                  \
    --description \"$DESCRIPTION\""

  CMD="$FPM -s dir -t $PACKAGE_TYPE \
    -n $PACKAGE_NAME -v $PACKAGE_VERSION \
    --iteration $PACKAGE_ITERATION \
    -a $PACKAGE_ARCH               \
    --log error                    \
    --config-files $INITD_DST      \
    --config-files $SYSTEMD_SYSCONFIG_DST \
    $PREUNINST_CMD                 \
    $POSTINST_CMD                  \
    $PACKAGE_DEPENDENCIES          \
    -p $OUTPUT_PKG_PATH            \
    $EPILOG \"$INSTALL_PREFIX/=/\""
  eval "$CMD"
  log "package created at $OUTPUT_PKG_PATH"

  # Generate debug packages for Linux or CentOS
  BUILD_DEBUG_PKG=false
  if [[ $PACKAGE_TYPE = "deb" ]]; then
    PACKAGE_DEBUG_NAME="$PACKAGE_NAME-dbg"
    PACKAGE_DEBUG_DEPENDENCIES="osquery (= $PACKAGE_VERSION-$PACKAGE_ITERATION)"

    # Debian only needs the non-stripped binaries.
    BINARY_DEBUG_DIR=$DEBUG_PREFIX/usr/lib/debug/usr/bin
    mkdir -p $BINARY_DEBUG_DIR
    cp "$BUILD_DIR/osquery/osqueryi" $BINARY_DEBUG_DIR
    cp "$BUILD_DIR/osquery/osqueryd" $BINARY_DEBUG_DIR
  elif [[ $PACKAGE_TYPE = "rpm" ]]; then
    PACKAGE_DEBUG_NAME="$PACKAGE_NAME-debuginfo"
    PACKAGE_DEBUG_DEPENDENCIES="osquery = $PACKAGE_VERSION"

    # Create Build-ID links for executables and Dwarfs.
    BUILD_ID_SHELL=`readelf -n "$BUILD_DIR/osquery/osqueryi" | grep "Build ID" | awk '{print $3}'`
    BUILD_ID_DAEMON=`readelf -n "$BUILD_DIR/osquery/osqueryd" | grep "Build ID" | awk '{print $3}'`
    BUILDLINK_DEBUG_DIR=$DEBUG_PREFIX/usr/lib/debug/.build-id/64
    if [[ ! "$BUILD_ID_SHELL" = "" ]]; then
      mkdir -p $BUILDLINK_DEBUG_DIR
      ln -s ../../../../bin/osqueryi $BUILDLINK_DEBUG_DIR/$BUILD_ID_SHELL
      ln -s ../../bin/osqueryi.debug $BUILDLINK_DEBUG_DIR/$BUILD_ID_SHELL.debug
      ln -s ../../../../bin/osqueryd $BUILDLINK_DEBUG_DIR/$BUILD_ID_DAEMON
      ln -s ../../bin/osqueryd.debug $BUILDLINK_DEBUG_DIR/$BUILD_ID_DAEMON.debug
    fi

    # Install the non-stripped binaries.
    BINARY_DEBUG_DIR=$DEBUG_PREFIX/usr/lib/debug/usr/bin/
    mkdir -p $BINARY_DEBUG_DIR
    cp "$BUILD_DIR/osquery/osqueryi" "$BINARY_DEBUG_DIR/osqueryi.debug"
    cp "$BUILD_DIR/osquery/osqueryd" "$BINARY_DEBUG_DIR/osqueryd.debug"

    # Finally install the source.
    SOURCE_DEBUG_DIR=$DEBUG_PREFIX/usr/src/debug/osquery-$PACKAGE_VERSION
    BUILD_DIR=`readlink --canonicalize "$BUILD_DIR"`
    SOURCE_DIR=`readlink --canonicalize "$SOURCE_DIR"`
    for file in `"$SCRIPT_DIR/getfiles.py" --build "$BUILD_DIR/" --base "$SOURCE_DIR/"`
    do
      mkdir -p `dirname "$SOURCE_DEBUG_DIR/$file"`
      cp "$SOURCE_DIR/$file" "$SOURCE_DEBUG_DIR/$file"
    done
  fi

  PACKAGE_DEBUG_DEPENDENCIES=`echo "$PACKAGE_DEBUG_DEPENDENCIES"|tr '-' '_'`
  OUTPUT_DEBUG_PKG_PATH=`realpath "$BUILD_DIR"`/$PACKAGE_DEBUG_NAME$(get_pkg_suffix)
  if [[ ! -z "$DEBUG" ]]; then
    rm -f $OUTPUT_DEBUG_PKG_PATH
    CMD="$FPM -s dir -t $PACKAGE_TYPE            \
      -n $PACKAGE_DEBUG_NAME -v $PACKAGE_VERSION \
      -a $PACKAGE_ARCH                           \
      --iteration $PACKAGE_ITERATION             \
      --log error                                \
      -d \"$PACKAGE_DEBUG_DEPENDENCIES\"         \
      -p $OUTPUT_DEBUG_PKG_PATH                  \
      $EPILOG \"$DEBUG_PREFIX/=/\""
    eval "$CMD"
    log "debug created at $OUTPUT_DEBUG_PKG_PATH"
  fi
}

main $@
