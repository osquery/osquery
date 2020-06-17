#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed in accordance with the terms specified in
#  the LICENSE file found in the root directory of this source tree.

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

function usage() {
  echo "${BASH_SOURCE[0]} destination-file"
}

function main() {
  if [[ $# < 1 ]]; then
    usage
    exit 1
  fi

  zip -j $1 $SCRIPT_DIR/../tests/configs/*.conf
}

main $@
