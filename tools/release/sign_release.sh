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

function usage() {
  echo "${BASH_SOURCE[0]} VERSION PATH_TO_OSQUERY SIGN_HOST SIGN_USER SIGN_IDENT"
  echo "  SIGN_HOST/SIGN_USER: hostname and user for signing machine"
  echo "  SIGN_IDENT: SSH identity for signing machine"
}

function main() {
  if [[ $# < 5 ]]; then
    usage
    exit 1
  fi

  VERSION=$1
  OSQUERY=$2
  HOST=$3
  USER=$4
  IDENT=$5

  PKGS=$OSQUERY/build/$VERSION
  if [[ ! -d "$PKGS" ]]; then
    echo "Cannot find $PKGS directory?"
    usage
    exit 1
  fi

  echo "[+] Copying packages from $PKGS to signing host $HOST"
  scp -i $IDENT -r $PKGS "$USER@$HOST":
  SSH="ssh -t -i $IDENT $USER@$HOST"

  $SSH "mv ./$VERSION/osquery-$VERSION-1.arch-x86_64.pkg.tar.xz ./local_packages/arch"
  $SSH "mv ./$VERSION/osquery-$VERSION.pkg ./local_packages/darwin"
  $SSH "mv ./$VERSION/osquery-debug-$VERSION.pkg ./local_packages/darwin"
  $SSH "mv ./$VERSION/osquery-$VERSION-1.darwin.i386.rpm ./local_packages/darwin"
  $SSH "mv ./$VERSION/osquery-debug-$VERSION-1.darwin.i386.rpm ./local_packages/darwin"
  $SSH "mv ./$VERSION/osquery-${VERSION}_1.linux_x86_64.tar.gz ./local_packages/linux"
  $SSH "cp ./$VERSION/osquery-$VERSION-1.linux.x86_64.rpm ./local_packages/rpm"
  $SSH "cp ./$VERSION/osquery-debuginfo-$VERSION-1.linux.x86_64.rpm ./local_packages/rpm"
  $SSH "cp ./$VERSION/osquery-$VERSION-1.linux.x86_64.rpm ./local_packages/centos6"
  $SSH "cp ./$VERSION/osquery-debuginfo-$VERSION-1.linux.x86_64.rpm ./local_packages/centos6"
  $SSH "cp ./$VERSION/osquery-$VERSION-1.linux.x86_64.rpm ./local_packages/centos7"
  $SSH "cp ./$VERSION/osquery-debuginfo-$VERSION-1.linux.x86_64.rpm ./local_packages/centos7"
  $SSH "cp ./$VERSION/osquery_${VERSION}_1.linux.amd64.deb ./local_packages/precise"
  $SSH "cp ./$VERSION/osquery-dbg_${VERSION}_1.linux.amd64.deb ./local_packages/precise"
  $SSH "cp ./$VERSION/osquery_${VERSION}_1.linux.amd64.deb ./local_packages/trusty"
  $SSH "cp ./$VERSION/osquery-dbg_${VERSION}_1.linux.amd64.deb ./local_packages/trusty"
  $SSH "cp ./$VERSION/osquery_${VERSION}_1.linux.amd64.deb ./local_packages/xenial"
  $SSH "cp ./$VERSION/osquery-dbg_${VERSION}_1.linux.amd64.deb ./local_packages/xenial"
  $SSH "cp ./$VERSION/osquery_${VERSION}_1.linux.amd64.deb ./local_packages/deb"
  $SSH "cp ./$VERSION/osquery-dbg_${VERSION}_1.linux.amd64.deb ./local_packages/deb"

  echo "[!] Now run: ./package_publisher please"
  $SSH "bash --login"

  echo "[+] Packages signed"
}

main $@
