#pragma once

/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/plugins/logger.h>
#include <osquery/registry_factory.h>

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


}

