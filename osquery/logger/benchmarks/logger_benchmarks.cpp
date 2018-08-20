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

#include <osquery/core.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

namespace osquery {

DECLARE_bool(disable_logging);

class DummyLoggerPlugin : public LoggerPlugin {
 public:
  bool usesLogStatus() override {
    return true;
  }

 protected:
  Status logString(const std::string& s) override {
    // Nothing.
    return Status(0);
  }

  void init(const std::string& name,
            const std::vector<StatusLogLine>& log) override {
    // Nothing.
  }

  Status logStatus(const std::vector<StatusLogLine>& log) override {
    // Nothing.
    return Status(0);
  }
};

static void LOGGER_logstatus_plugin(benchmark::State& state) {
  FLAGS_disable_logging = false;
  auto& rf = RegistryFactory::get();
  rf.registry("logger")->add("dummy", std::make_shared<DummyLoggerPlugin>());
  auto active = rf.getActive("logger");
  rf.setActive("logger", "dummy");

  initStatusLogger("benchmark", false);
  initLogger("benchmark");

  FLAGS_logtostderr = false;
  FLAGS_stderrthreshold = google::GLOG_WARNING;
  while (state.KeepRunning()) {
    LOG(INFO) << "INFO";
    relayStatusLogs();
  }

  rf.setActive("logger", active);
  FLAGS_logtostderr = true;
  FLAGS_stderrthreshold = google::GLOG_INFO;
  FLAGS_disable_logging = true;
}

BENCHMARK(LOGGER_logstatus_plugin);

static void LOGGER_logstring_plugin(benchmark::State& state) {
  FLAGS_disable_logging = false;
  auto& rf = RegistryFactory::get();
  rf.registry("logger")->add("dummy", std::make_shared<DummyLoggerPlugin>());

  auto active = rf.getActive("logger");
  rf.setActive("logger", "dummy");

  while (state.KeepRunning()) {
    logString("{}", "");
  }

  rf.setActive("logger", active);
  FLAGS_disable_logging = true;
}

BENCHMARK(LOGGER_logstring_plugin);
}
