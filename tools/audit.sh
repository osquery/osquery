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

function check_executable() {
  HERE=$(pwd)
  cd $SCRIPT_DIR/..;
  FILES=$(find osquery -type f -perm -a=x)
  if [[ ! -z "$FILES" ]]; then
    echo "[!] Some source files are marked executable:"
    echo "$FILES"
    false
  fi

  FILES=$(find include -type f -perm -a=x)
  if [[ ! -z "$FILES" ]]; then
    echo "[!] Some header files are marked executable:"
    echo "$FILES"
    false
  fi
  cd $HERE;
}

function audit() {
  log "Running various code/change audits!"

  echo ""
  log "Initializing and updating all submodules"
  checkout_thirdparty

  echo ""
  log "Checking for source files marked executable"
  check_executable

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
