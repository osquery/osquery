#!/usr/bin/env bash

# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

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
