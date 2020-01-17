#!/bin/sh
# Copyright (c) Facebook, Inc. and its affiliates. All Rights Reserved

# Could be called by DPKG or RPM.
# Handle the cases we want to hook or silently claim success.
case "$1" in
configure | 2)
    : # Fall through to systemctl handle.
    ;;
*)
    exit 0
    ;;
esac

# Create 'osquery' group for extensions socket.
if ! getent group osquery >/dev/null; then
    addgroup --system osquery --quiet
fi

# Set group owner for directory to 'osquery'.
chgrp osquery /var/osquery

# Make sure 'osquery' group is inherited by extensions socket so
# it's writable for group members.
chmod 2775 /var/osquery

# If we have a systemd, daemon-reload away now
if [ -x /bin/systemctl ] && pidof systemd; then
    /bin/systemctl daemon-reload 2>/dev/null 2>&1
fi
