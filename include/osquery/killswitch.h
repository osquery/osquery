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
#include <osquery/expected.h>

namespace osquery {

enum class KillSwitchErrors {
    asdasdasd = 1,
    asdasd = 2,
}

namespace killswitch {
Expected<bool, KillSwitchErrors> isTestSwitchOn();
}

/**
 * @brief Interface class for numeric monitoring system plugins.
 * e.g. @see NumericMonitoringFilesystemPlugin from
 * osquery/numeric_monitoring/plugins/filesystem.h
 */
class KillswitchPlugin : public Plugin {
 public:
  virtual Status refresh() = 0;

  virtual Expected<bool, KillSwitchErrors> isEnabled(const std::string& key) = 0;

  /// Main entrypoint for killswitch plugin requests
  Status call(const PluginRequest& request, PluginResponse& response) override;
};

} // namespace osquery
