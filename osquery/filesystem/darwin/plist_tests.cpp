// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/filesystem.h"

#include <boost/filesystem.hpp>

#include <glog/logging.h>
#include <gtest/gtest.h>

#include "osquery/core/darwin/test_util.h"

using namespace osquery::core;
namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

char* argv0;

namespace osquery {

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
  EXPECT_THROW(tree.get<bool>("foobar"), pt::ptree_bad_path);
  EXPECT_EQ(tree.get<std::string>("Label"), "com.apple.FileSyncAgent.sshd");
  std::vector<std::string> program_arguments = {
      "/System/Library/CoreServices/FileSyncAgent.app/Contents/Resources/"
      "FileSyncAgent_sshd-keygen-wrapper",
      "-i",
      "-f",
      "/System/Library/CoreServices/FileSyncAgent.app/Contents/Resources/"
      "FileSyncAgent_sshd_config",
  };
  pt::ptree program_arguments_tree = tree.get_child("ProgramArguments");
  std::vector<std::string> program_arguments_parsed;
  for (const auto& argument : program_arguments_tree) {
    program_arguments_parsed.push_back(argument.second.get<std::string>(""));
  }
  EXPECT_EQ(program_arguments_parsed, program_arguments);
}

TEST_F(PlistTests, test_parse_plist_content_with_blobs) {
  pt::ptree tree;

  fs::path bin_path(argv0);
  auto s = parsePlist((bin_path.parent_path() / "../../../../tools/test_binary.plist").string()l, tree);
  EXPECT_TRUE(s.ok());
  EXPECT_EQ(s.toString(), "OK");
  EXPECT_THROW(tree.get<bool>("foobar"), pt::ptree_bad_path);
  EXPECT_EQ(tree.get<std::string>("SessionItems.Controller"), "CustomListItems");
  auto first_element = tree.get_child("SessionItems.CustomListItems").begin()->second;
  EXPECT_EQ(first_element.get<std::string>("Name"), "Flux");
  std::string alias = first_element.get<std::string>("Alias");
  // Verify we parsed the binary blob correctly
  EXPECT_NE(alias.find("Applications/Flux.app"), std::string::npos);
}
}

int main(int argc, char* argv[]) {
  argv0 = argv[0];
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
