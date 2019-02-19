/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <string>
#include <unordered_map>

#include <gtest/gtest_prod.h>

#include <osquery/core.h>
#include <osquery/killswitch.h>
#include <osquery/plugins/plugin.h>
#include <osquery/query.h>
#include <osquery/utils/expected/expected.h>
#include <osquery/utils/mutex.h>

namespace osquery {

/**
 * @brief Interface class for killswitch plugins.
 */
class KillswitchPlugin : public Plugin {
 public:
  /// Main entrypoint for killswitch plugin requests
  virtual Status call(const PluginRequest& request,
                      PluginResponse& response) override;

 protected:
  void addCacheEntry(const std::string& key, bool value);
  void setCache(const std::unordered_map<std::string, bool>& killswitchMap);

  enum class ParseMapJSONError {
    IncorrectKeyType = 1,
    IncorrectValueType = 2,
    UnknownParsingProblem = 3,
    MissingKey = 4
  };
  static Expected<std::unordered_map<std::string, bool>, ParseMapJSONError>
  parseMapJSON(const std::string& content);

 private:
  enum class IsEnabledError { NoKeyFound = 1 };
  Expected<bool, IsEnabledError> isEnabled(const std::string& key);
  std::unordered_map<std::string, bool> killswitchMap_;
  mutable Mutex mutex_;

 private:
  FRIEND_TEST(KillswitchTests, test_killswitch_plugin);
  FRIEND_TEST(KillswitchFilesystemTests,
              test_killswitch_filesystem_plugin_legit);
};
} // namespace osquery
