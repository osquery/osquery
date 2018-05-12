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
  GENJSON="$SCRIPT_DIR/../codegen/genwebsitejson.py"
  /usr/local/osquery/bin/python "$GENJSON" --specs "$OSQUERY/specs" > "$SITE/src/data/osquery_schema_versions/$VERSION.json"

  echo "[+] Writing new version metadata"
  GENMETADATA="$SCRIPT_DIR/../codegen/genwebsitemetadata.py"
  /usr/local/osquery/bin/python "$GENMETADATA" --file "$SITE/src/data/osquery_metadata.json" --version "$VERSION"

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

  PACKAGE="$URL/windows/osquery-$VERSION.msi"
  echo "[+] Downloading $PACKAGE"
  WINDOWS=$(curl $PACKAGE | shasum -a 256 | awk '{print $1}')

  PACKAGE="$URL/darwin/osquery-debug-$VERSION.pkg"
  echo "[+] Downloading $PACKAGE"
  DEBUG_DARWIN=$(curl $PACKAGE | shasum -a 256 | awk '{print $1}')

  PACKAGE="$URL/rpm/osquery-debuginfo-$VERSION-1.linux.x86_64.rpm"
  echo "[+] Downloading $PACKAGE"
  DEBUG_RPM=$(curl $PACKAGE | shasum -a 256 | awk '{print $1}')

  PACKAGE="$URL/deb/osquery-dbg_${VERSION}_1.linux.amd64.deb"
  echo "[+] Downloading $PACKAGE"
  DEBUG_DEB=$(curl $PACKAGE | shasum -a 256 | awk '{print $1}')

  PACKAGES="$SITE/src/data/osquery_package_versions/${VERSION}.json"
  rm -f "${PACKAGES}"
  cat << EOF >> ${PACKAGES}
{
  "version": "$VERSION",
  "downloads": {
    "official": [
      {
        "type": "macOS",
        "package": "osquery-$VERSION.pkg",
        "content": "$DARWIN",
        "url": "https://pkg.osquery.io/darwin/osquery-$VERSION.pkg"
      },
      {
        "type": "Linux",
        "package": "osquery-$VERSION_1.linux_x86_64.tar.gz",
        "content": "$LINUX",
        "url": "https://pkg.osquery.io/linux/osquery-$VERSION_1.linux_x86_64.tar.gz"
      },
      {
        "type": "RPM",
        "package": "osquery-$VERSION-1.linux.x86_64.rpm",
        "content": "$RPM",
        "url": "https://pkg.osquery.io/rpm/osquery-$VERSION-1.linux.x86_64.rpm"
      },
      {
        "type": "Debian",
        "package": "osquery_$VERSION_1.linux.amd64.deb",
        "content": "$DEB",
        "url": "https://pkg.osquery.io/deb/osquery_$VERSION_1.linux.amd64.deb"
      },
      {
        "type": "Windows",
        "package": "osquery-$VERSION.msi",
        "content": "$WINDOWS",
        "url": "https://pkg.osquery.io/windows/osquery-$VERSION.msi"
      }
    ],
    "debug": [
      {
        "type": "macOS",
        "package": "osquery-debug-$VERSION.pkg",
        "content": "$DEBUG_DARWIN",
        "url": "https://pkg.osquery.io/darwin/osquery-debug-$VERSION.pkg"
      },
      {
        "type": "RPM",
        "package": "osquery-debuginfo-$VERSION-1.linux.x86_64.rpm",
        "content": "$DEBUG_RPM",
        "url": "https://pkg.osquery.io/rpm/osquery-debuginfo-$VERSION-1.linux.x86_64.rpm"
      },
      {
        "type": "Debian",
        "package": "osquery-dbg_2.10.2_1.linux.amd64.deb",
        "content": "$DEBUG_DEB",
        "url": "https://pkg.osquery.io/deb/osquery-dbg_$VERSION_1.linux.amd64.deb"
      }
    ]
  }
}
EOF
  echo "[+] Hashes written to $PACKAGES"



  echo "[+] Finished"
}

main $@
