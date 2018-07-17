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
#include <unordered_map>

#include <osquery/core.h>
#include <osquery/expected.h>
#include <osquery/killswitch.h>
#include <osquery/mutex.h>
#include <osquery/plugin.h>
#include <osquery/query.h>

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
    UnknownParsingProblem = 3
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
  FRIEND_TEST(KillswitchFilesystemTests, test_killswitch_filesystem_plugin);
};
} // namespace osquery
