#!/bin/sh

# we could be called by dpkg or rpm, handle the cases we want to hook
# or silently claim success
case "$1" in
  # debian/ubuntu
  configure)
    : # fall through to systemctl handle
    ;;
  # fedora/redhat
  [1-9]*)
    # this becomes '2' or more if it's an upgrade (during rpm transaction)
    if [ $1 -eq 1 ]; then
      exit 0
    fi
    ;;
  *)
    exit 0
    ;;
esac

# if we have a systemd, daemon-reload away now
if [ -x /bin/systemctl ] ; then
  systemctl daemon-reload
fi
