/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "osquery/killswitch/killswitch_refreshable_plugin.h"
#include <string>

namespace osquery {

class KillswitchFilesystem : public KillswitchRefreshablePlugin {
 public:
  KillswitchFilesystem();
  KillswitchFilesystem(const boost::filesystem::path& conf_path);

 protected:
  ExpectedSuccess<KillswitchRefreshablePlugin::RefreshError> refresh() override;

 private:
  const boost::filesystem::path conf_path_;

  FRIEND_TEST(KillswitchFilesystemTests, test_killswitch_filesystem_plugin);
};

} // namespace osquery
