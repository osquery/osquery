#!/bin/bash

# Unload and remove com.facebook.osquery.plist launchdaemon
osquery_launchd=/Library/LaunchDaemons/com.facebook.osqueryd.plist
if [ -f $osquery_launchd ]; then
  if launchctl list | grep "com.facebook*"; then
    launchctl unload $osquery_launchd
  fi
  rm $osquery_launchd
fi

# Remove files created by osquery pkg
declare -a osquery_dirs=("/private/var/log/osquery" "/private/var/osquery" "/usr/local/bin/osquery*")
for dir in "${osquery_dirs[@]}"
do
  rm -rf $dir
done

if pkgutil --pkgs | grep "com.facebook.osquery"; then
  # Forget package receipt
  pkgutil --forget com.facebook.osquery
fi
