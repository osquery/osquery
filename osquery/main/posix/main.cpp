/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/system.h>
#include <osquery/logger/logger.h>
#include <osquery/main/main.h>

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
