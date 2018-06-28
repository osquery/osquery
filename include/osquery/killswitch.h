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

#include <string>

#include <osquery/core.h>
#include <osquery/plugin.h>
#include <osquery/query.h>

namespace osquery {

/**
 * @brief Interface class for numeric monitoring system plugins.
 * e.g. @see NumericMonitoringFilesystemPlugin from
 * osquery/numeric_monitoring/plugins/filesystem.h
 */
class KillswitchPlugin : public Plugin {
 public:
  virtual Status isEnabled(std::string switchKe, bool& isEnabled) = 0;

  virtual Status refresh() = 0;

  /// Main entrypoint for killswitch plugin requests
  Status call(const PluginRequest& request, PluginResponse& response) override;
};

} // namespace osquery
