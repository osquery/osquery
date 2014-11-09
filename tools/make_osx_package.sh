#!/usr/bin/env bash

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
export PATH="$PATH:/usr/local/bin"

source $SCRIPT_DIR/lib.sh

APP_IDENTIFIER="com.facebook.osqueryd"
OUTPUT_PKG_PATH="$SCRIPT_DIR/../osqueryd.pkg"
LAUNCHD_PATH="$SCRIPT_DIR/$APP_IDENTIFIER.plist"
LAUNCHD_INSTALL_PATH="/Library/LaunchDaemons/$APP_IDENTIFIER.plist"
OSQUERY_LOG_DIR="/var/log/osquery/"
OSQUERY_CONFIG_PATH_DEST="/var/osquery/osquery.conf"
OSQUERY_CONFIG_PATH_SOURCE=""

APP_VERSION=`git describe --tags HEAD`

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
  fatal "Usage: $0 -c path/to/your/osquery.conf"
}

function parse_args() {
  while [ "$1" != "" ]; do
    case $1 in
      -c | --config )         shift
                              OSQUERY_CONFIG_PATH_SRC=$1
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
    usage
  fi

  if [[ ! -f $OSQUERY_CONFIG_PATH_SRC ]]; then
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

  log "calculating dependency tree"
  dependency_list=("${BREW_PACKAGES[@]}")
  for package in ${BREW_PACKAGES[*]}; do
    for dep in `brew deps $package`; do
      if ! contains_element $dep "${dependency_list[@]}"; then
        dependency_list+=($dep)
      fi
    done
  done

  log "copying dependencies"
  for dep in ${dependency_list[*]}; do
    dep_dir=`brew info $dep | grep Cellar | awk '{print $1}'`
    brew unlink $dep 2>&1  1>/dev/null
    links=`brew link --dry-run $dep`
    brew link --overwrite $dep 2>&1  1>/dev/null
    echo "    - $dep ($dep_dir)"
    mkdir -p $INSTALL_PREFIX`dirname $dep_dir`
    cp -r $dep_dir $INSTALL_PREFIX`dirname $dep_dir`
    for link in $links; do
      if [[ $link = $BREW_PREFIX* ]]; then
        target="`dirname $link`/`ls -l $link | awk '{print $11}'`"
        echo "mkdir -p `dirname $link`" >> $POSTINSTALL
        echo "rm -rf $link" >> $POSTINSTALL
        echo "ln -s $target $link" >> $POSTINSTALL
        echo "" >> $POSTINSTALL
      fi
    done
  done

  log "copying osquery binaries"
  BINARY_INSTALL_DIR="$INSTALL_PREFIX/usr/local/bin/"
  mkdir -p $BINARY_INSTALL_DIR
  cp $SCRIPT_DIR/../build/darwin/osquery/osqueryi $BINARY_INSTALL_DIR
  cp $SCRIPT_DIR/../build/darwin/osquery/osqueryd $BINARY_INSTALL_DIR
  mkdir -p $INSTALL_PREFIX/$OSQUERY_LOG_DIR
  mkdir -p `dirname $INSTALL_PREFIX$OSQUERY_CONFIG_PATH_DEST`
  cp $OSQUERY_CONFIG_PATH_SRC $INSTALL_PREFIX$OSQUERY_CONFIG_PATH_DEST

  log "copying osquery configurations"
  mkdir -p `dirname $INSTALL_PREFIX$LAUNCHD_INSTALL_PATH`
  cp $LAUNCHD_PATH $INSTALL_PREFIX$LAUNCHD_INSTALL_PATH

  log "finalizing preinstall and postinstall scripts"
  echo "$POSTINSTALL_ADDITIONAL_TEXT" >> $POSTINSTALL

  log "creating package"
  pkgbuild --root $INSTALL_PREFIX       \
           --scripts $SCRIPT_ROOT       \
           --identifier $APP_IDENTIFIER \
           --version $APP_VERSION       \
           $OUTPUT_PKG_PATH 2>&1  1>/dev/null
  log "package created at $OUTPUT_PKG_PATH"
}

main $@
