/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tests/test_util.h"

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

void genApplication(const pt::ptree& tree,
                    const fs::path& path,
                    QueryData& results);
void genApplicationsFromPath(const fs::path& path, std::set<std::string>& apps);

pt::ptree getInfoPlistTree() {
  std::string content;
  readFile(kTestDataPath + "test_info.plist", content);

  pt::ptree tree;
  parsePlistContent(content, tree);
  return tree;
}

class AppsTests : public testing::Test {};

TEST_F(AppsTests, test_parse_info_plist) {
  QueryData results;
  // Generate a set of results/single row using an example tree.
  auto tree = getInfoPlistTree();
  genApplication(tree, "/Applications/Foobar.app/Contents/Info.plist", results);
  ASSERT_EQ(results.size(), 1U);
  ASSERT_EQ(results[0].count("name"), 1U);

  Row expected = {
      {"name", "Foobar.app"},
      {"path", "/Applications/Foobar.app"},
      {"bundle_executable", "Photo Booth"},
      {"bundle_identifier", "com.apple.PhotoBooth"},
      {"bundle_name", ""},
      {"bundle_short_version", "6.0"},
      {"bundle_version", "517"},
      {"bundle_package_type", "APPL"},
      {"environment", ""},
      {"element", ""},
      {"compiler", "com.apple.compilers.llvm.clang.1_0"},
      {"development_region", "English"},
      {"display_name", ""},
      {"info_string", ""},
      {"minimum_system_version", "10.7.0"},
      {"category", "public.app-category.entertainment"},
      {"applescript_enabled", ""},
      {"copyright", ""},
  };

  // We could compare the entire map, but iterating the columns will produce
  // better error text as most likely parsing for a certain column/type changed.
  for (const auto& column : expected) {
    EXPECT_EQ(results[0][column.first], column.second);
  }
}

TEST_F(AppsTests, test_sanity_check) {
  // Test beyond units, that there's at least 1 application on the built host.
  std::set<std::string> apps;
  genApplicationsFromPath("/Applications", apps);
  ASSERT_GT(apps.size(), 0U);

  // Parse each application searching for a parsed Safari.
  bool found_safari = false;
  for (const auto& path : apps) {
    pt::ptree tree;
    if (osquery::parsePlist(path, tree).ok()) {
      QueryData results;
      genApplication(tree, path, results);

      // No asserts about individual Application parsing, expect edge cases.
      if (results.size() > 0 && results[0].count("bundle_identifier") > 0 &&
          results[0].at("bundle_identifier") == "com.apple.Safari") {
        // Assume Safari is installed on the build host.
        found_safari = true;
        break;
      }
    }
  }

  EXPECT_TRUE(found_safari);
}
}
}
