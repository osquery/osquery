#!/bin/sh

#  Copyright (c) 2015, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

URL=https://osquery-packages.s3.amazonaws.com

function usage() {
  echo "${BASH_SOURCE[0]} VERSION PATH_TO_OSQUERY PATH_TO_SITE"
}

function main() {
  if [[ $# < 3 ]]; then
    usage
    exit 1
  fi

  VERSION=$1
  OSQUERY=$2
  SITE=$3

  echo "[+] Checking out version $VERSION"
  (cd $OSQUERY; git checkout $VERSION)

  echo "[+] Writing new table API"
  GENAPI="$OSQUERY/tools/codegen/genapi.py"
  /usr/local/osquery/bin/python "$GENAPI" --tables "$OSQUERY/specs" > "$SITE/schema/$VERSION.json"

  echo "[+] Checkout out master"
  (cd $OSQUERY; git checkout master)

  printf "[+] Downloading and hashing packages...\n"
  PACKAGE="$URL/linux/osquery-${VERSION}_1.linux_x86_64.tar.gz"
  echo "[+] Downloading $PACKAGE"
  LINUX=$(curl $PACKAGE | shasum -a 256 | awk '{print $1}')

  PACKAGE="$URL/deb/osquery_${VERSION}_1.linux.amd64.deb"
  echo "[+] Downloading $PACKAGE"
  DEB=$(curl $PACKAGE | shasum -a 256 | awk '{print $1}')

  PACKAGE="$URL/rpm/osquery-$VERSION-1.linux.x86_64.rpm"
  echo "[+] Downloading $PACKAGE"
  RPM=$(curl $PACKAGE | shasum -a 256 | awk '{print $1}')

  PACKAGE="$URL/darwin/osquery-$VERSION.pkg"
  echo "[+] Downloading $PACKAGE"
  DARWIN=$(curl $PACKAGE | shasum -a 256 | awk '{print $1}')

  PACKAGE="$URL/darwin/osquery-debug-$VERSION.pkg"
  echo "[+] Downloading $PACKAGE"
  DEBUG_DARWIN=$(curl $PACKAGE | shasum -a 256 | awk '{print $1}')

  PACKAGE="$URL/rpm/osquery-debuginfo-$VERSION-1.linux.x86_64.rpm"
  echo "[+] Downloading $PACKAGE"
  DEBUG_RPM=$(curl $PACKAGE | shasum -a 256 | awk '{print $1}')

  PACKAGE="$URL/deb/osquery-dbg_${VERSION}_1.linux.amd64.deb"
  echo "[+] Downloading $PACKAGE"
  DEBUG_DEB=$(curl $PACKAGE | shasum -a 256 | awk '{print $1}')

  EXISTING=$(cat $OSQUERY/docs/_data/versions.yml)
  OUTPUT="$OSQUERY/docs/_data/versions.yml"
  rm -f "${OUTPUT}"
  cat << EOF >> ${OUTPUT}
- version: $VERSION
  linux: $LINUX
  deb: $DEB
  darwin: $DARWIN
  rpm: $RPM
  debug:
    deb: $DEBUG_DEB
    darwin: $DEBUG_DARWIN
    rpm: $DEBUG_RPM

$EXISTING
EOF
  echo "[+] Hashes written to $OUTPUT"
  echo "[+] Finished"
}

main $@
