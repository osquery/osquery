/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <string>

#include <boost/filesystem/path.hpp>

#include <osquery/killswitch/killswitch_refreshable_plugin.h>
#include <osquery/utils/config/default_paths.h>

namespace osquery {

class KillswitchFilesystem : public KillswitchRefreshablePlugin {
 public:
  KillswitchFilesystem();
  KillswitchFilesystem(const boost::filesystem::path& conf_path);

 protected:
  ExpectedSuccess<KillswitchRefreshablePlugin::RefreshError> refresh() override;

 private:
  const boost::filesystem::path conf_path_;

  FRIEND_TEST(KillswitchFilesystemTests,
              test_killswitch_filesystem_plugin_legit);
  FRIEND_TEST(KillswitchFilesystemTests,
              test_killswitch_filesystem_plugin_incorrect_key);
  FRIEND_TEST(KillswitchFilesystemTests,
              test_killswitch_filesystem_plugin_incorrect_value);
  FRIEND_TEST(KillswitchFilesystemTests,
              test_killswitch_filesystem_plugin_incorrect_no_table);
};

} // namespace osquery
