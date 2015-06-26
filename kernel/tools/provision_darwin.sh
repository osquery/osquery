#!/usr/bin/env bash

#  Copyright (c) 2014, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

set -e

if [[ ! -z "$KERNEL" ]]; then
  KERNEL=kernel.${KERNEL}
else
  KERNEL=kernel
fi

KERNEL_SUFFIX="kcsuffix=$KERNEL -v pmuflags=1"
BOOT_ARGS=kext-dev-mode=1

function disable_signatures() {
  # Run on guest VMs
  echo ""
  echo "WARNING: Disabling kernel extension signature checking..."
  sudo nvram boot-args="$BOOT_ARGS"
  echo "WARNING: Reboot required."
  echo ""
}

function configure_target() {
  # Run on guest VMs
  echo ""
  echo "WARNING: Configuring kernel to break/debug (BE CAREFUL)..."
  sudo nvram boot-args="$BOOT_ARGS $KERNEL_SUFFIX"
  echo "WARNING: Reboot required."
  echo ""
}

function enable_signatures() {
  # Run on guest VMs
  echo ""
  echo "NOTICE: Clearing nvram boot args (enabling signatures)..."
  sudo nvram boot-args=""
  echo "NOTICE: Reboot required."
  echo ""
}

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

function main() {
  if [[ $1 == "enable" ]]; then
    disable_signatures
  elif [[ $1 == "debug" ]]; then
    debug
  elif [[ $1 == "configure" ]]; then
    configure_target
  elif [[ $1 == "disable" ]]; then
    enable_signatures
  fi
}

main $@
