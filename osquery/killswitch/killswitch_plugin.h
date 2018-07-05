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
#include <osquery/expected.h>
#include <osquery/plugin.h>
#include <osquery/query.h>

namespace osquery {
/**
 * @brief Interface class for killswitch plugins.
 */
class KillswitchPlugin : public Plugin {
 public:
  enum class IsEnabledError { NoKeyFound = 1 };

 public:
  /// Main entrypoint for killswitch plugin requests
  virtual Status call(const PluginRequest& request,
                      PluginResponse& response) override;

 protected:
  void clearCache();
  void addCacheEntry(const std::string& key, bool value);
  Expected<bool, IsEnabledError> isEnabled(const std::string& key);

 private:
  std::map<std::string, bool> killswitchMap;

 private:
  FRIEND_TEST(KillswitchTests, test_killswitch_plugin);
};
} // namespace osquery
