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
#include <thread>

#include <scribe/client/ScribeClient.h>

#include <osquery/flags.h>
#include <osquery/logger.h>

namespace osquery {

DEFINE_osquery_flag(string,
                    active_scribe_category,
                    "osquery",
                    "The path of the scribe category to be used if scribe "
                    "logging is enabled.");

DEFINE_osquery_flag(bool,
                    dev_machine,
                    false,
                    "Set to true if the machine is a dev machine.");

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
