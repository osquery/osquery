/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/database.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/core/test_util.h"

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

std::vector<std::string> getLaunchdFiles();
Row parseLaunchdItem(const std::string& path, const pt::ptree& tree);

pt::ptree getLaunchdTree() {
  std::string content;
  readFile(kTestDataPath + "test_launchd.plist", content);

  pt::ptree tree;
  parsePlistContent(content, tree);
  return tree;
}

class LaunchdTests : public testing::Test {};

TEST_F(LaunchdTests, test_parse_launchd_item) {
  auto tree = getLaunchdTree();
  Row expected = {
      {"path", "/Library/LaunchDaemons/Foobar.plist"},
      {"name", "Foobar.plist"},
      {"label", "com.apple.mDNSResponder"},
      {"run_at_load", ""},
      {"keep_alive", ""},
      {"on_demand", "false"},
      {"disabled", ""},
      {"username", "_mdnsresponder"},
      {"groupname", "_mdnsresponder"},
      {"stdout_path", ""},
      {"stderr_path", ""},
      {"start_interval", ""},
      {"program_arguments", "/usr/sbin/mDNSResponder"},
      {"program", ""},
      {"watch_paths", ""},
      {"queue_directories", ""},
      {"inetd_compatibility", ""},
      {"start_on_mount", ""},
      {"root_directory", ""},
      {"working_directory", ""},
      {"process_type", ""},
  };
  EXPECT_EQ(parseLaunchdItem("/Library/LaunchDaemons/Foobar.plist", tree),
            expected);
}
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
