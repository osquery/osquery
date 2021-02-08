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

  # dict format is keyword="value" or just "value" - so we need to make sure our output is quoted.

  egrep -h -R -o "HasMember\\(\"([^\"]+)\"\\)" $SCRIPT_DIR/../../osquery $SCRIPT_DIR/../../plugins  | sed 's/HasMember(//' | sed 's/)//' > tmp
  egrep -h -o -e "\"([^\"]+)\"" $SCRIPT_DIR/../tests/configs/*.conf >> tmp
  egrep -h -o -e "\"([^\"]+)\"" $SCRIPT_DIR/../../packs/*.conf >> tmp
  egrep -h -R -o "FLAG\(.*\)" $SCRIPT_DIR/../../osquery $SCRIPT_DIR/../../plugins | awk -F ', ' '{ print "\""$2"\"" }' >> tmp

  sort tmp | uniq > $1
  rm tmp
}

main $@
