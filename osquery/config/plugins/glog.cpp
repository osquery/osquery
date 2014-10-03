#include "osquery/logger/plugin.h"

#include <glog/logging.h>

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
