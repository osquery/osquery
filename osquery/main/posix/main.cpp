/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/main/main.h"

namespace osquery {

Status installService(const char* const path) {
  LOG(INFO) << "The --install service flag only applies to Windows platforms";
  return Status(1);
}

Status uninstallService() {
  LOG(INFO) << "The --uninstall service flag only applies to Windows platforms";
  return Status(1);
}
} // namespace osquery

int main(int argc, char* argv[]) {
  // On POSIX systems we can jump immediately into startOsquery.
  // A short abstraction exists to allow execute-as-service checks in Windows.
  return osquery::startOsquery(argc, argv);
}
