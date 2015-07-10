#!/usr/bin/env bash
set -e

KERNEL_EXTENSION_IDENTIFIER="com.facebook.security.osquery"

if kextstat | grep -qcm1 $KERNEL_EXTENSION_IDENTIFIER; then
  tries=5
  n=0
  until [ $n -ge $tries ]; do
    kextunload -b $KERNEL_EXTENSION_IDENTIFIER && break
    n=$[$n+1]
    sleep 1  # We need to know the daemon has stopped for long enough for the
    # kernel extension to allow unloading.
  done
  if [ $n -ge $tries ]; then
    exit 1
  fi
fi
