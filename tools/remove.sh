#!/bin/bash
# Basic Removal Script for OSX

function log() {
  echo "[+] $1"
}

function fatal() {
  echo "[!] $1"
  exit 1
}

if [[ -f "/etc/pf.conf" ]]; then
  # darwin
  echo "[-] Removing: /usr/local/lib/libosquery.dylib"
  rm /usr/local/lib/libosquery.dylib
  echo "[-] Removing: /usr/local/bin/osqueryi"
  rm /usr/local/bin/osqueryi
  echo "[-] Removing: /usr/local/bin/osqueryd"
  rm /usr/local/bin/osqueryd
  echo "Complete: osquery Removed"
elif [[ -f "/etc/dpkg/dpkg.cfg" ]]; then
  # ubuntu
  echo "[!] The removal script doesn't support Ubuntu.... yet."
elif [[ -f "/etc/yum.conf" ]]; then
  # centos
  echo "[!] The removal script doesn't support CentOS.... yet."
fi

echo ""
echo "If you had problems consider opening an issue on github.com/facebook/osquery"
