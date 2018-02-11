/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/dispatcher.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/remote/bro/broker_manager.h"

namespace fs = boost::filesystem;

namespace osquery {

DECLARE_bool(logger_event_type);
DECLARE_bool(disable_distributed);
DECLARE_string(distributed_plugin);

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
            const std::vector<StatusLogLine>& log) override{};

 private:
};

REGISTER(BroLoggerPlugin, "logger", "bro");

Status BroLoggerPlugin::setUp() {
  if (FLAGS_disable_distributed) {
    return Status(1, "The distributed service is disabled");
  }

  if (FLAGS_distributed_plugin != "bro") {
    return Status(1, "The distributed bro service is disabled");
  }

  if (FLAGS_logger_event_type) {
    return Status(1, "Bro logger cannot use event type logging");
  }
  return Status(0, "OK");
}

Status BroLoggerPlugin::logString(const std::string& s) {
  QueryLogItem item;
  Status status = deserializeQueryLogItemJSON(s, item);
  if (!status) {
    return Status(1, "Failed to deserialize");
  }
  return BrokerManager::get().logQueryLogItemToBro(item);
}

Status BroLoggerPlugin::logSnapshot(const std::string& s) {
  return logString(s);
}

Status BroLoggerPlugin::logStatus(const std::vector<StatusLogLine>& log) {
  return Status(1, "Not implemented");
}
} // namespace osquery
