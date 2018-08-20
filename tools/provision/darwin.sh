#!/usr/bin/env bash

#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

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
  do_sudo $GEM install --no-ri --no-rdoc fpm
}

[ "$0" = "$BASH_SOURCE" ] && vagrant_setup || true
