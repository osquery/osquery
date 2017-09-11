/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

// clang-format off
#include <windows.h>
#include <evntprov.h>
// clang-format on

#include <osquery/flags.h>
#include <osquery/logger.h>

namespace osquery {

class WindowsEventLoggerPlugin : public LoggerPlugin {
 public:
  virtual ~WindowsEventLoggerPlugin();

  bool usesLogStatus() override {
    return true;
  }

 protected:
  Status logString(const std::string& s) override;
  void init(const std::string& name,
            const std::vector<StatusLogLine>& log) override;
  Status logStatus(const std::vector<StatusLogLine>& log) override;

 private:
  REGHANDLE registration_handle_{0};
};
}
