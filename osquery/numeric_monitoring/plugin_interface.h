/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <chrono>
#include <string>

#include <osquery/core.h>
#include <osquery/plugins/plugin.h>
#include <osquery/query.h>
#include <osquery/utils/expected/expected.h>

#include <osquery/numeric_monitoring.h>

namespace osquery {
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
