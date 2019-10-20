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
#   Set FPM if installed outside of path

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
SOURCE_DIR="$SCRIPT_DIR/../.."
BUILD_DIR=${BUILD_DIR:="$SOURCE_DIR/build/linux"}
FPM=${FPM:="fpm"}
INSTALL_SOURCE=0

source "$SOURCE_DIR/tools/lib.sh"

# Default version
VERSION=`(cd $SOURCE_DIR; git describe --tags HEAD) || echo 'unknown-version'`
PACKAGE_VERSION=${OSQUERY_BUILD_VERSION:="$VERSION"}

DESCRIPTION="osquery is an operating system instrumentation toolchain."
PACKAGE_NAME="osquery"
PACKAGE_ARCH="x86_64"
PACKAGE_VENDOR="osquery"
PACKAGE_LICENSE="Apache 2.0 or GPL 2.0"

PACKAGE_TYPE=""
PACKAGE_ITERATION_DEFAULT="1.linux"
PACKAGE_ITERATION_ARCH="1.arch"

PACKAGE_DEB_DEPENDENCIES="libc6 (>=2.12), zlib1g"
PACKAGE_RPM_DEPENDENCIES="glibc >= 2.12, zlib"
PACKAGE_TGZ_DEPENDENCIES="zlib"
PACKAGE_TAR_DEPENDENCIES="none"

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
LENSES_LICENSE="${SOURCE_DIR}/libraries/cmake/source/augeas/src/COPYING"
LENSES_SRC="${SOURCE_DIR}/libraries/cmake/source/augeas/src/lenses"
LENSES_DST="/usr/share/osquery/lenses/"
OSQUERY_POSTINSTALL=${OSQUERY_POSTINSTALL:-"$SCRIPT_DIR/linux_postinstall.sh"}
OSQUERY_PREUNINSTALL=${OSQUERY_PREUNINSTALL:-""}
OSQUERY_CONFIG_SRC=${OSQUERY_CONFIG_SRC:-""}
OSQUERY_TLS_CERT_CHAIN_SRC=${OSQUERY_TLS_CERT_CHAIN_SRC:-""}
OSQUERY_TLS_CERT_CHAIN_BUILTIN_SRC="${SCRIPT_DIR}/certs.pem"
OSQUERY_TLS_CERT_CHAIN_BUILTIN_DST="/usr/share/osquery/certs/certs.pem"
OSQUERY_EXAMPLE_CONFIG_SRC="$SCRIPT_DIR/osquery.example.conf"
OSQUERY_EXAMPLE_CONFIG_DST="/usr/share/osquery/osquery.example.conf"
OSQUERY_LOG_DIR="/var/log/osquery/"
OSQUERY_VAR_DIR="/var/osquery"
OSQUERY_ETC_DIR="/etc/osquery"

function usage() {
  fatal "Usage: $0 -t deb|rpm|pacman|tar
    [-b|--build] /path/to/build/dir
    [-d|--dependencies] DEPENDENCY_LIST string
    [-i|--iteration] REVISION
    [-u|--preuninst] /path/to/pre-uninstall
    [-p|--postinst] /path/to/post-install
    [-c|--config] /path/to/embedded.config
    [-v|--version] OSQUERY_BUILD_VERSION override

  This will generate an Linux package with:
    (1) An example config /usr/share/osquery/osquery.example.conf
    (2) An init.d script /etc/init.d/osqueryd
    (3) A systemd service file /usr/lib/systemd/system/osqueryd.service and
        a sysconfig file /etc/{default|sysconfig}/osqueryd as appropriate
    (4) A default TLS certificate bundle (provided by cURL)
    (5) The osquery toolset /usr/bin/osquery*"
}

function check_parsed_args() {
  if [[ -z $PACKAGE_TYPE ]]; then
    usage
  fi

  if [[ ! -d $BUILD_DIR ]]; then
    log "Cannot find build dir [-b|--build]: $BUILD_DIR"
    usage
  fi

  if [ ! -z "$OSQUERY_CONFIG_SRC" ] && [ ! -f "$OSQUERY_CONFIG_SRC" ]; then
    log "$OSQUERY_CONFIG_SRC is not a file."
    usage
  fi

  if ! command -v $FPM > /dev/null; then
    fatal "Cannot find fpm script (is fpm installed?)"
  fi
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
      -b | --build )          shift
                              BUILD_DIR=$1
                              ;;
      -v | --version )        shift
                              PACKAGE_VERSION=$1
                              ;;
      -s | --source )         INSTALL_SOURCE=1
                              ;;
      -h | --help )           usage
                              ;;
    esac
    shift
  done

  check_parsed_args

  if [[ -z $PACKAGE_ITERATION ]]; then
    if [[ $PACKAGE_TYPE == "pacman" ]]; then
      PACKAGE_ITERATION=$PACKAGE_ITERATION_ARCH
    else
      PACKAGE_ITERATION=$PACKAGE_ITERATION_DEFAULT
    fi
  fi

  if [[ -z $PACKAGE_DEPENDENCIES ]]; then
    if [[ $PACKAGE_TYPE == "deb" ]]; then
      PACKAGE_DEPENDENCIES=$PACKAGE_DEB_DEPENDENCIES
    elif [[ $PACKAGE_TYPE == "rpm" ]]; then
      PACKAGE_DEPENDENCIES=$PACKAGE_RPM_DEPENDENCIES
    elif [[ $PACKAGE_TYPE == "pacman" ]]; then
      PACKAGE_DEPENDENCIES=$PACKAGE_TGZ_DEPENDENCIES
    else
      PACKAGE_DEPENDENCIES=$PACKAGE_TAR_DEPENDENCIES
    fi
  fi

  if [[ $PACKAGE_VERSION == *"-"* ]]; then
    DESCRIPTION="$DESCRIPTION (unstable/latest version)"
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

  WORKING_DIR=$BUILD_DIR/_packaging
  INSTALL_PREFIX=$WORKING_DIR/prefix
  DEBUG_PREFIX=$WORKING_DIR/debug

  platform OS
  distro $OS DISTRO

  OUTPUT_PKG_PATH=`readlink --canonicalize "$BUILD_DIR"`/$PACKAGE_NAME$(get_pkg_suffix)

  rm -rf $WORKING_DIR
  rm -f $OUTPUT_PKG_PATH
  mkdir -p $INSTALL_PREFIX

  log "copying osquery binaries to $INSTALL_PREFIX"
  BINARY_INSTALL_DIR="$INSTALL_PREFIX/usr/bin/"
  mkdir -p $BINARY_INSTALL_DIR
  cp "$BUILD_DIR/osquery/osqueryd" $BINARY_INSTALL_DIR
  ln -s osqueryd $BINARY_INSTALL_DIR/osqueryi
  strip --strip-debug $BINARY_INSTALL_DIR/*
  cp "$CTL_SRC" $BINARY_INSTALL_DIR

  # Create the prefix log dir and copy source configs
  log "copying osquery configurations to $INSTALL_PREFIX"
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

  if [[ ! -z $OSQUERY_CONFIG_SRC ]] && [[ -f $OSQUERY_CONFIG_SRC ]]; then
    log "copying optional config into $INSTALL_PREFIX$OSQUERY_ETC_DIR"
    cp $OSQUERY_CONFIG_SRC $INSTALL_PREFIX/$OSQUERY_ETC_DIR/osquery.conf
  fi

  if [[ ! -z $OSQUERY_TLS_CERT_CHAIN_SRC ]] && [[ -f $OSQUERY_TLS_CERT_CHAIN_SRC ]]; then
    log "copying optional tls server certs file into $INSTALL_PREFIX$OSQUERY_ETC_DIR"
    cp $OSQUERY_TLS_CERT_CHAIN_SRC $INSTALL_PREFIX/$OSQUERY_ETC_DIR/tls-server-certs.pem
  fi

  if [[ ! -z $OSQUERY_TLS_CERT_CHAIN_BUILTIN_SRC ]] && [[ -f $OSQUERY_TLS_CERT_CHAIN_BUILTIN_SRC ]]; then
    log "copying built-in tls server certs file into $INSTALL_PREFIX$OSQUERY_TLS_CERT_CHAIN_BUILTIN_DST"
    mkdir -p `dirname $INSTALL_PREFIX/$OSQUERY_TLS_CERT_CHAIN_BUILTIN_DST`
    cp $OSQUERY_TLS_CERT_CHAIN_BUILTIN_SRC $INSTALL_PREFIX/$OSQUERY_TLS_CERT_CHAIN_BUILTIN_DST
  fi

  if [[ $PACKAGE_TYPE = "deb" ]]; then
    #Change config path to Ubuntu default
    SYSTEMD_SYSCONFIG_DST=$SYSTEMD_SYSCONFIG_DST_DEB
  fi

  log "copying osquery init scripts into $INSTALL_PREFIX"
  mkdir -p `dirname $INSTALL_PREFIX$INITD_DST`
  mkdir -p `dirname $INSTALL_PREFIX$SYSTEMD_SERVICE_DST`
  mkdir -p `dirname $INSTALL_PREFIX$SYSTEMD_SYSCONFIG_DST`
  cp $INITD_SRC $INSTALL_PREFIX$INITD_DST
  cp $SYSTEMD_SERVICE_SRC $INSTALL_PREFIX$SYSTEMD_SERVICE_DST
  cp $SYSTEMD_SYSCONFIG_SRC $INSTALL_PREFIX$SYSTEMD_SYSCONFIG_DST

  if [[ $PACKAGE_TYPE = "deb" ]]; then
    #Change config path in service unit
    sed -i 's/sysconfig/default/g' $INSTALL_PREFIX$SYSTEMD_SERVICE_DST
    #Change config path in initd script
    sed -i 's/sysconfig/default/g' $INSTALL_PREFIX$INITD_DST
  fi

  log "creating $PACKAGE_TYPE package"
  IFS=',' read -a deps <<< "$PACKAGE_DEPENDENCIES"
  PACKAGE_DEPENDENCIES=
  for element in "${deps[@]}"
  do
    element=`echo $element | sed 's/ *$//'`
    PACKAGE_DEPENDENCIES="$PACKAGE_DEPENDENCIES -d \"$element\""
  done

  POSTINST_CMD=""
  if [[ ! -z $OSQUERY_POSTINSTALL ]] && [[ -f $OSQUERY_POSTINSTALL ]]; then
    POSTINST_CMD="--after-install $OSQUERY_POSTINSTALL"
  fi

  PREUNINST_CMD=""
  if [[ ! -z $OSQUERY_PREUNINSTALL ]] && [[ -f $OSQUERY_PREUNINSTALL ]]; then
    PREUNINST_CMD="--before-remove $OSQUERY_PREUNINSTALL"
  fi

  # Change directory modes
  find $INSTALL_PREFIX/ -type d | xargs chmod 755

  EPILOG="--url https://osquery.io \
    -m osquery@osquery.io          \
    --vendor \"$PACKAGE_VENDOR\"       \
    --license \"$PACKAGE_LICENSE\" \
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
    BUILD_DEBUG_PKG=true
    PACKAGE_DEBUG_NAME="$PACKAGE_NAME-dbg"
    PACKAGE_DEBUG_DEPENDENCIES="osquery (= $PACKAGE_VERSION-$PACKAGE_ITERATION)"

    # Debian only needs the non-stripped binaries.
    BINARY_DEBUG_DIR=$DEBUG_PREFIX/usr/lib/debug/usr/bin
    mkdir -p $BINARY_DEBUG_DIR
    cp "$BUILD_DIR/osquery/osqueryd" $BINARY_DEBUG_DIR
    strip --only-keep-debug "$BINARY_DEBUG_DIR/osqueryd"
    ln -s osqueryd $BINARY_DEBUG_DIR/osqueryi
  elif [[ $PACKAGE_TYPE = "rpm" ]]; then
    BUILD_DEBUG_PKG=true
    PACKAGE_DEBUG_NAME="$PACKAGE_NAME-debuginfo"
    PACKAGE_DEBUG_DEPENDENCIES="osquery = $PACKAGE_VERSION"

    # Create Build-ID links for executables and Dwarfs.
    BUILD_ID=`readelf -n "$BUILD_DIR/osquery/osqueryd" | grep "Build ID" | awk '{print $3}'`
    if [[ ! "$BUILD_ID" = "" ]]; then
      BUILDLINK_DEBUG_DIR=$DEBUG_PREFIX/usr/lib/debug/.build-id/${BUILD_ID:0:2}
      mkdir -p $BUILDLINK_DEBUG_DIR
      ln -sf ../../../../bin/osqueryd $BUILDLINK_DEBUG_DIR/${BUILD_ID:2}
      ln -sf ../../bin/osqueryd.debug $BUILDLINK_DEBUG_DIR/${BUILD_ID:2}.debug
    fi

    # Install the non-stripped binaries.
    BINARY_DEBUG_DIR=$DEBUG_PREFIX/usr/lib/debug/usr/bin/
    mkdir -p $BINARY_DEBUG_DIR
    cp "$BUILD_DIR/osquery/osqueryd" "$BINARY_DEBUG_DIR/osqueryd.debug"
    strip --only-keep-debug "$BINARY_DEBUG_DIR/osqueryd.debug"
    ln -s osqueryd "$BINARY_DEBUG_DIR/osqueryi.debug"

    # Finally install the source.
    if [[ $INSTALL_SOURCE == "1" ]]; then
      SOURCE_DEBUG_DIR=$DEBUG_PREFIX/usr/src/debug/osquery-$PACKAGE_VERSION
      BUILD_DIR=`readlink --canonicalize "$BUILD_DIR"`
      SOURCE_DIR=`readlink --canonicalize "$SOURCE_DIR"`
      for file in `"$SCRIPT_DIR/getfiles.py" --build "$BUILD_DIR/" --base "$SOURCE_DIR/"`
      do
        mkdir -p `dirname "$SOURCE_DEBUG_DIR/$file"`
        cp "$file" "$SOURCE_DEBUG_DIR/$file"
      done
    fi
  fi

  PACKAGE_DEBUG_DEPENDENCIES=`echo "$PACKAGE_DEBUG_DEPENDENCIES"|tr '-' '_'`
  OUTPUT_DEBUG_PKG_PATH=`readlink --canonicalize "$BUILD_DIR"`/$PACKAGE_DEBUG_NAME$(get_pkg_suffix)
  if [[ "$BUILD_DEBUG_PKG" = "true" ]]; then
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
