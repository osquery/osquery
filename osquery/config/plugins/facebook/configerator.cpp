/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <algorithm>
#include <functional>
#include <thread>

#include <configerator/distribution/api/api.h>
#include <configerator/structs/osquery/gen-cpp/osquery_types.h>

#include <osquery/config.h>
#include <osquery/logger.h>

using osquery::Status;

namespace osquery {

class ConfigeratorConfigPlugin : public ConfigPlugin {
 public:
  ConfigeratorConfigPlugin(){};

  std::pair<osquery::Status, std::string> genConfig() {
    facebook::configerator::ConfigeratorApi api;
    std::string content;
    api.getConfig("osquery/osquery", &content);
    return std::make_pair(Status(0, "OK"), content);
  }

  virtual ~ConfigeratorConfigPlugin() {}
};

REGISTER_CONFIG_PLUGIN("configerator",
                       std::make_shared<osquery::ConfigeratorConfigPlugin>());
}
