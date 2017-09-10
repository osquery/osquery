/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iostream>

#include <evntprov.h>
#include <windows.h>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/logger/plugins/windows_event_log.h"
#include "osquery/logger/plugins/windows_event_log_manifest/osquery.h"

namespace osquery {

REGISTER(WindowsEventLoggerPlugin, "logger", "windowseventlog");

Status WindowsEventLoggerPlugin::logString(const std::string& s) {
  std::cout << s << std::endl;
  return Status(0, "OK");
}

Status WindowsEventLoggerPlugin::logStatus(
    const std::vector<StatusLogLine>& log) {
  for (const auto& item : log) {
    std::string line = "severity=" + std::to_string(item.severity) +
                       " location=" + item.filename + ":" +
                       std::to_string(item.line) + " message=" + item.message;

    std::cout << line << std::endl;
  }

  return Status(0, "OK");
}

void WindowsEventLoggerPlugin::init(const std::string& name,
                                    const std::vector<StatusLogLine>& log) {
  logStatus(log);
}
}
