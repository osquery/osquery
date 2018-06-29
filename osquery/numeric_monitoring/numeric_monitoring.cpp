/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/numeric_monitoring.h>
#include <osquery/numeric_monitoring/plugin_interface.h>
#include <osquery/registry_factory.h>

namespace osquery {

FLAG(bool,
     enable_numeric_monitoring,
     false,
     "Enable numeric monitoring system");
FLAG(string,
     numeric_monitoring_plugins,
     "filesystem",
     "Coma separated numeric monitoring plugins names");

namespace monitoring {

void record(const std::string& path, ValueType value, TimePoint timePoint) {
  if (!FLAGS_enable_numeric_monitoring) {
    return;
  }
  auto status =
      Registry::call(registryName(),
                     FLAGS_numeric_monitoring_plugins,
                     {
                         {recordKeys().path, path},
                         {recordKeys().value, std::to_string(value)},
                         {recordKeys().timestamp,
                          std::to_string(timePoint.time_since_epoch().count())},
                     });
  if (!status.ok()) {
    LOG(ERROR) << "Failed to send numeric monitoring record: " << status.what();
  }
}

} // namespace monitoring
} // namespace osquery
