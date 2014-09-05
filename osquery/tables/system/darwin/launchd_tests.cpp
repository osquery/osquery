// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>
#include <glog/logging.h>

#include "osquery/core/darwin/test_util.h"
#include "osquery/database.h"
#include "osquery/filesystem.h"

using namespace osquery::core;
using namespace osquery::db;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

std::vector<std::string> getLaunchdFiles();
Row parseLaunchdItem(const std::string& path, const pt::ptree& tree);

class LaunchdTests : public testing::Test {};

TEST_F(LaunchdTests, test_parse_launchd_item) {
  auto tree = getLaunchdTree();
  Row expected = {{"path", "/Library/LaunchDaemons/Foobar.plist"},
                  {"name", "Foobar.plist"},
                  {"label", "com.apple.mDNSResponder"},
                  {"run_at_load", ""},
                  {"keep_alive", ""},
                  {"on_demand", "false"},
                  {"disabled", ""},
                  {"user_name", "_mdnsresponder"},
                  {"group_name", "_mdnsresponder"},
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
                  {"process_type", ""}, };
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
