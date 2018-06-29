/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <chrono>
#include <string>

#include <osquery/core.h>
#include <osquery/plugin.h>
#include <osquery/query.h>

#include <osquery/numeric_monitoring.h>

namespace osquery {

namespace monitoring {

struct RecordKeys {
  std::string path;
  std::string value;
  std::string timestamp;
  std::string aggregation;
};

const RecordKeys& recordKeys();

const char* registryName();

} // namespace monitoring

/**
 * @brief Interface class for numeric monitoring system plugins.
 * e.g. @see NumericMonitoringFilesystemPlugin from
 * osquery/numeric_monitoring/plugins/filesystem.h
 */
class NumericMonitoringPlugin : public Plugin {
 public:
  Status call(const PluginRequest& request, PluginResponse& response) override;
};

} // namespace osquery
