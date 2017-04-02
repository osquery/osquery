/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/flags.h>
#include <osquery/logger.h>

namespace osquery {

class StdoutLoggerPlugin : public LoggerPlugin {
 public:
  bool usesLogStatus() override {
    return true;
  }

 protected:
  Status logString(const std::string& s) override;

  void init(const std::string& name,
            const std::vector<StatusLogLine>& log) override;

  Status logStatus(const std::vector<StatusLogLine>& log) override;
};

REGISTER(StdoutLoggerPlugin, "logger", "stdout");

Status StdoutLoggerPlugin::logString(const std::string& s) {
  printf("%s\n", s.c_str());
  return Status(0, "OK");
}

Status StdoutLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
  for (const auto& item : log) {
    std::string line = "severity=" + std::to_string(item.severity) +
                       " location=" + item.filename + ":" +
                       std::to_string(item.line) + " message=" + item.message;

    printf("%s\n", line.c_str());
  }
  return Status(0, "OK");
}

void StdoutLoggerPlugin::init(const std::string& name,
                              const std::vector<StatusLogLine>& log) {
  // Stop the internal Glog facilities.
  FLAGS_alsologtostderr = false;
  FLAGS_logtostderr = false;

  // Now funnel the intermediate status logs provided to `init`.
  logStatus(log);
}
}
