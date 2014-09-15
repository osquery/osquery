// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/logger/plugin.h"

#include <algorithm>
#include <thread>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include <scribe/client/ScribeClient.h>

using osquery::Status;

namespace osquery {

DEFINE_string(
    active_scribe_category,
    "osquery",
    "The path of the scribe category to be used if scribe logging is enabled.");

DEFINE_bool(dev_machine, false, "Set to true if the machine is a dev machine.");

class ScribeLoggerPlugin : public LoggerPlugin {
 public:
  ScribeLoggerPlugin() {}

  Status logString(const std::string& message) {
    std::string category = FLAGS_active_scribe_category;
    if (FLAGS_dev_machine) {
      category += "_dev";
    }
    scribe::ScribeClient::get()->put(category, message);
    return Status(0, "OK");
  }

  virtual ~ScribeLoggerPlugin() {}
};

REGISTER_LOGGER_PLUGIN("scribe",
                       std::make_shared<osquery::ScribeLoggerPlugin>());
}
