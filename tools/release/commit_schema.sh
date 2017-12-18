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
  echo "${BASH_SOURCE[0]} VERSION PATH_TO_SITE"
}

function main() {
  if [[ $# < 2 ]]; then
    usage
    exit 1
  fi

  VERSION=$1
  SITE=$2

  (cd $SITE/schema; git add .)
  echo "[+] Will commit the following schema files: "
  FILES=$(cd $SITE; git --no-pager diff --name-only HEAD)
  if [[ $FILES = "" ]]; then
    echo "[-] No files to commit" && exit 1
  fi

  echo $FILES
  echo

  read -p "Are you sure? [y/N]: " -r
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1
  fi

  (cd $SITE; git commit -m "Adding schema $VERSION")
  read -p "Push to master? [y/N]: " -r
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1
  fi

  (cd $SITE; git push)
  echo "[+] Finished"
}

main $@
