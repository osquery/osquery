/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/expected.h>
#include <osquery/killswitch/killswitch_plugin.h>

namespace osquery {

/**
 * @brief Interface class for killswitch plugins.
 */
class KillswitchRefreshablePlugin : public KillswitchPlugin {
 public:
  static const char refresh_str[];
  Status setUp() override;

  /// Main entrypoint for killswitch plugin requests
  virtual Status call(const PluginRequest& request,
                      PluginResponse& response) override;

 protected:
  enum class RefreshError { NoContentReached = 1, ParsingError = 2 };
  virtual ExpectedSuccess<RefreshError> refresh() = 0;
};
} // namespace osquery
