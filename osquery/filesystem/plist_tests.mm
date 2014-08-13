// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/filesystem.h"

#include <glog/logging.h>
#include <gtest/gtest.h>

#import <Foundation/Foundation.h>

#include "osquery/core/test_util.h"

using namespace osquery::core;
namespace pt = boost::property_tree;

namespace osquery { namespace fs {

class PlistTests : public testing::Test {};

TEST_F(PlistTests, test_parse_plist) {
  std::string path = "/System/Library/LaunchDaemons/com.apple.kextd.plist";
  boost::property_tree::ptree tree;
  auto s = parsePlist(path, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
}

TEST_F(PlistTests, test_parse_plist_content) {
  std::string content = getPlistContent();
  pt::ptree tree;
  auto s = parsePlistContent(content, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_EQ(tree.get<bool>("Disabled"), true);
  EXPECT_EQ(tree.get<std::string>("Label"), "com.apple.FileSyncAgent.sshd");
  std::vector<std::string> program_arguments = {
    "/System/Library/CoreServices/FileSyncAgent.app/Contents/Resources/FileSyncAgent_sshd-keygen-wrapper",
    "-i",
    "-f",
    "/System/Library/CoreServices/FileSyncAgent.app/Contents/Resources/FileSyncAgent_sshd_config",
  };
  pt::ptree program_arguments_tree = tree.get_child("ProgramArguments");
  std::vector<std::string> program_arguments_parsed;
  for (const auto& argument : program_arguments_tree) {
      program_arguments_parsed.push_back(argument.second.get<std::string>(""));
  }
  EXPECT_EQ(program_arguments_parsed, program_arguments);
}

}}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
