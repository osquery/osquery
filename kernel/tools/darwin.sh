#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

set -e

if [[ ! -z "$KERNEL" ]]; then
  KERNEL=kernel.${KERNEL}
else
  KERNEL=kernel
fi

function debug() {
  # Run on host/debugger/development.
  if [[ ! -x /System/Library/Kernels/kernel ]]; then
    sudo cp /Library/Developer/KDKs/*/System/Library/Kernels/$KERNEL \
      /System/Library/Kernels/
  fi
  touch ~/.lldbinit
  (grep -q -F 'settings set target.load-script-from-symbol-file true' ~/.lldbinit \
    || echo "settings set target.load-script-from-symbol-file true" >> ~/.lldbinit)
  lldb /Library/Developer/KDKs/*/System/Library/Kernels/$KERNEL
}

function sign() {
  _path=$2
  _identity=$1
  sudo codesign -s "$_identity" "$_path"
}

function main() {
  if [[ $1 == "debug" ]]; then
    debug
  elif [[ $1 == "sign" ]]; then
    sign $2 $3
  fi
}

main $@
