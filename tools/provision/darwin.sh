#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed in accordance with the terms specified in
#  the LICENSE file found in the root directory of this source tree.

DARWIN_SETUP="\
if [[ ! -f /var/.osquery_build ]]; then \
touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress; \
PROD=\$(softwareupdate -l | grep \"\\*.*Command Line\" | \
  tail -n 1 | awk -F\"*\" '{print \$2}' | sed -e 's/^ *//' | tr -d '\n' \
); \
softwareupdate -i \"\$PROD\" --verbose; \
sudo touch /var/.osquery_build; \
fi; \
"

function vagrant_setup() {
  sudo bash -c "$DARWIN_SETUP"
}

function distro_main() {
  GEM=`which gem`
  do_sudo $GEM install --no-ri --no-rdoc -n /usr/local/bin fpm
}

[ "$0" = "$BASH_SOURCE" ] && vagrant_setup || true
