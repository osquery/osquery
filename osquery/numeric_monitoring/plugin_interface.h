/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <chrono>
#include <string>

#include <osquery/core/core.h>
#include <osquery/core/plugins/plugin.h>
#include <osquery/core/query.h>
#include <osquery/utils/expected/expected.h>

#include <osquery/numeric_monitoring/numeric_monitoring.h>

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
