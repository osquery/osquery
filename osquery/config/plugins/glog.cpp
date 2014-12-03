// Copyright 2004-present Facebook. All Rights Reserved.

#include <glog/logging.h>

#include <osquery/logger/plugin.h>

namespace osquery {

class GlogPlugin : public LoggerPlugin {
 public:
  Status logString(const std::string& message) {
    LOG(INFO) << message;
    return Status(0, "OK");
  }

  virtual ~GlogPlugin() {}
};

REGISTER_LOGGER_PLUGIN("glog", std::make_shared<osquery::GlogPlugin>());
}
