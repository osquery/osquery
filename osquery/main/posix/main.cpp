/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/main/main.h>
#include <osquery/system.h>

namespace osquery {

Status installService(const std::string& /*path*/) {
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
