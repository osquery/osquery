/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <osquery/killswitch/killswitch_refreshable_plugin.h>

namespace osquery {

class TLSKillswitchPlugin;

class TLSKillswitchPlugin
    : public KillswitchRefreshablePlugin,
      public std::enable_shared_from_this<TLSKillswitchPlugin> {
 public:
  Status setUp() override;

 protected:
  ExpectedSuccess<KillswitchRefreshablePlugin::RefreshError> refresh() override;
  /// Calculate the URL once and cache the result.
  std::string uri_;
};
} // namespace osquery
