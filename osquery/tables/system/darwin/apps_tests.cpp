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
#include <glog/logging.h>

#include <osquery/filesystem.h>
#include <osquery/tables.h>

#include "osquery/core/test_util.h"

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

std::vector<std::string> getSystemApplications();
std::string getNameFromInfoPlistPath(const std::string& path);
std::string getPathFromInfoPlistPath(const std::string& path);
Row parseInfoPlist(const std::string& path, const pt::ptree& tree);

pt::ptree getInfoPlistTree() {
  std::string content;
  readFile(core::kTestDataPath + "test_info.plist", content);

  pt::ptree tree;
  parsePlistContent(content, tree);
  return tree;
}

class AppsTests : public testing::Test {};

TEST_F(AppsTests, get_name_from_info_plist_path) {
  EXPECT_EQ(
      "Foo.app",
      getNameFromInfoPlistPath("/Applications/Foo.app/Contents/Info.plist"));
  EXPECT_EQ("Foo Bar.app",
            getNameFromInfoPlistPath(
                "/Applications/Foo Bar.app/Contents/Info.plist"));
  EXPECT_EQ("Foo.app",
            getNameFromInfoPlistPath(
                "/Users/marpaia/Applications/Foo.app/Contents/Info.plist"));
  EXPECT_EQ("Foo Bar.app",
            getNameFromInfoPlistPath(
                "/Users/marpaia/Applications/Foo Bar.app/Contents/Info.plist"));
}

TEST_F(AppsTests, get_path_from_info_plist_path) {
  EXPECT_EQ(
      "/Applications/Foo.app",
      getPathFromInfoPlistPath("/Applications/Foo.app/Contents/Info.plist"));
  EXPECT_EQ("/Applications/Foo Bar.app",
            getPathFromInfoPlistPath(
                "/Applications/Foo Bar.app/Contents/Info.plist"));
  EXPECT_EQ("/Users/marpaia/Applications/Foo.app",
            getPathFromInfoPlistPath(
                "/Users/marpaia/Applications/Foo.app/Contents/Info.plist"));
  EXPECT_EQ("/Users/marpaia/Applications/Foo Bar.app",
            getPathFromInfoPlistPath(
                "/Users/marpaia/Applications/Foo Bar.app/Contents/Info.plist"));
}

TEST_F(AppsTests, test_parse_info_plist) {
  auto tree = getInfoPlistTree();
  Row expected = {
      {"name", "Foobar.app"},
      {"path", "/Applications/Foobar.app"},
      {"bundle_executable", "Photo Booth"},
      {"bundle_identifier", "com.apple.PhotoBooth"},
      {"bundle_name", ""},
      {"bundle_short_version", "6.0"},
      {"bundle_version", "517"},
      {"bundle_package_type", "APPL"},
      {"compiler", "com.apple.compilers.llvm.clang.1_0"},
      {"development_region", "English"},
      {"display_name", ""},
      {"info_string", ""},
      {"minimum_system_version", "10.7.0"},
      {"category", "public.app-category.entertainment"},
      {"applescript_enabled", ""},
      {"copyright", ""},
  };
  EXPECT_EQ(
      parseInfoPlist("/Applications/Foobar.app/Contents/Info.plist", tree),
      expected);
}
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
