/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <benchmark/benchmark.h>

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include "osquery/tests/test_util.h"

namespace osquery {

class NoneLoggerPlugin : public LoggerPlugin {
 public:
  Status setUp() override {
    return Status(0);
  }

  Status logString(const std::string& s) override {
    return Status(0);
  }

  Status logStatus(const std::vector<StatusLogLine>& log) override {
    return Status(0);
  }

  void init(const std::string& name,
            const std::vector<StatusLogLine>& log) override {}
};

REGISTER(NoneLoggerPlugin, "logger", "none");

DECLARE_string(logger_plugin);
}

int main(int argc, char *argv[]) {
  osquery::FLAGS_logger_plugin = "none";

  osquery::initTesting();

  // Optionally enable Goggle Logging
  google::InitGoogleLogging(argv[0]);

  ::benchmark::Initialize(&argc, argv);
  ::benchmark::RunSpecifiedBenchmarks();
  return 0;
}
