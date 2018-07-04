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

#include <map>
#include <string>

#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/expected.h>
#include <osquery/plugin.h>
#include <osquery/query.h>

namespace osquery {
/**
 * @brief Interface class for killswitch plugins.
 */
class KillswitchPlugin : public Plugin {
 public:
  Status setUp() override;

  /// Main entrypoint for killswitch plugin requests
  Status call(const PluginRequest& request, PluginResponse& response) override;

 protected:
  void clearCache();
  Status addCacheEntry(const std::string& key, bool value);
  virtual Status refresh() = 0;
  Status isEnabled(const std::string& key, bool& isEnabled);

 private:
  std::map<std::string, bool> killswitchMap;

  friend class TestKillswitchPlugin;
};
} // namespace osquery
