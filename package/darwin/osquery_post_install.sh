#!/bin/bash
#
# Copyright 2004-present Facebook. All Rights Reserved.

OSQUERY_LAUNCD_STRING="osquery"
OSQUERY_LAUNCD_LABEL="com.facebook.osquery.plist"
OSQUERY_LAUNCD_PATH="/Library/LaunchDaemons/$OSQUERY_LAUNCD_LABEL"
OSQUERY_PROCESS_STRING="osqueryd"

function log() {
  echo "[+] $@"
}

function run() {
  "$@"
  local status=$?
  if [ $status -ne 0 ]; then
    log "command \"$@\" failed with exit code: $status"
  fi
  return $status
}

function main() {
  if launchctl list | grep -qcm1 $OSQUERY_LAUNCD_STRING; then
    log "$OSQUERY_LAUNCD_PATH already loaded. Unloading."
    run launchctl stop $OSQUERY_LAUNCD_LABEL
    run launchctl unload $OSQUERY_LAUNCD_PATH
  fi

  log "Loading $OSQUERY_LAUNCD_PATH"
  run launchctl load $OSQUERY_LAUNCD_PATH
}

main
