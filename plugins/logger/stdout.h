#pragma once

/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/plugins/logger.h>
#include <osquery/registry/registry_factory.h>

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

