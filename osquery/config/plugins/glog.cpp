/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

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
