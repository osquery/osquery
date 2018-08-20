#!/bin/bash

#  Copyright (c) 2015, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
VAGRANT="/vagrant"

DARWIN_BOX="macos10.13"
LINUX_BOX="ubuntu16.04"

function usage() {
  echo "${BASH_SOURCE[0]} dependency_name"
}

function install_deps() {
  BOX=$1
  DEPS=$2

  echo "[+] Uninstalling and reinstalling dependency(s)..."
  for DEP in $(echo "$DEPS" | tr "," " ") ; do
    INSTALL_CMD="cd /vagrant; \
      ./tools/provision.sh uninstall osquery/osquery-local/$DEP; \
      ./tools/provision.sh install osquery/osquery-local/$DEP; \
      ./tools/provision.sh bottle osquery/osquery-local/$DEP; \
    "

    vagrant ssh $BOX -c "$INSTALL_CMD"

    if [[ "$BOX" = "$DARWIN_BOX" ]]; then
      vagrant scp "$BOX:$VAGRANT/*$DEP*.tar.gz" .
      vagrant scp "$BOX:$VAGRANT/tools/provision/formula/$DEP.rb" \
        ./tools/provision/formula/$DEP.rb
    fi
  done

}

function main() {
  if [[ $# < 1 ]]; then
    usage
    exit 1
  fi

  CURRENT_DIR=$(pwd)
  DEPS=$1

  DEPS_CMD="cd $VAGRANT; make sysprep || true"

  echo "[+] Vagrant up $LINUX_BOX"
  OSQUERY_BUILD_CPUS=4 vagrant up $LINUX_BOX
  echo "[+] Building linux deps..."
  vagrant ssh $LINUX_BOX -c "$DEPS_CMD"
  install_deps $LINUX_BOX "$DEPS"
  vagrant halt $LINUX_BOX

  echo "[+] Vagrant up $DARWIN_BOX"
  OSQUERY_BUILD_CPUS=4 vagrant up $DARWIN_BOX
  echo "[+] Running initial softwareupdate check..."
  vagrant ssh $DARWIN_BOX -c "$VAGRANT/tools/provision/darwin.sh"
  echo "[+] Running build command for macOS..."
  vagrant ssh $DARWIN_BOX -c "$DEPS_CMD"
  install_deps $DARWIN_BOX "$DEPS"
  vagrant halt $DARWIN_BOX

  echo "[+] Finished"
  cd $CURRENT_DIR
}

main $@
