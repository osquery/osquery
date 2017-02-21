/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/dispatcher.h>
#include <osquery/logger.h>
#include <osquery/status.h>

#include <exception>

#include <osquery/registry.h>

#include "osquery/bro/BrokerManager.h"
#include "osquery/bro/QueryManager.h"

namespace fs = boost::filesystem;

namespace osquery {

class BroLoggerPlugin : public LoggerPlugin {
 public:
  Status setUp() override;

  /// Log results (differential) to a distinct path.
  Status logString(const std::string& s) override;

  /// Log snapshot data to a distinct path.
  Status logSnapshot(const std::string& s) override;

  /// Write a status to Bro.
  Status logStatus(const std::vector<StatusLogLine>& log) override;

  /**
   * @brief Initialize the logger plugin after osquery has begun.
   *
   */
  void init(const std::string& name,
            const std::vector<StatusLogLine>& log) override;

 private:
};

REGISTER(BroLoggerPlugin, "logger", "bro");

Status BroLoggerPlugin::setUp() {
  return Status(0, "OK");
}

Status BroLoggerPlugin::logString(const std::string& s) {
  QueryLogItem item;
  Status status = deserializeQueryLogItemJSON(s, item);
  if (status.getCode() == 0) {
    // printQueryLogItemJSON(s);
  } else {
    LOG(ERROR) << "Parsing query result FAILED";
    return Status(1, "Failed to deserialize QueryLogItem");
  }
  return BrokerManager::getInstance()->logQueryLogItemToBro(item);
}

Status BroLoggerPlugin::logSnapshot(const std::string& s) {
  // LOG(ERROR) << "logSnapshot = " << s;
  return this->logString(s);
}

Status BroLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
  LOG(ERROR) << "logStatus = ";
  // NOT IMPLEMENTED
  return Status(1, "Not implemented");
}

void BroLoggerPlugin::init(const std::string& name,
                           const std::vector<StatusLogLine>& log) {}
}
