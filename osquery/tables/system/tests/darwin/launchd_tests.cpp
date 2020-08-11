/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/core/sql/query_data.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/darwin/plist.h>

namespace fs = boost::filesystem;
namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

// From the launchd table implementation.
void genLaunchdItem(const pt::ptree& tree,
                    const fs::path& path,
                    QueryData& results);

class LaunchdTests : public testing::Test {};

TEST_F(LaunchdTests, test_parse_launchd_item) {
  // Read the contents of our testing launchd plist.
  pt::ptree tree;
  auto launchd_path = getTestConfigDirectory() / "test_launchd.plist";
  auto status = osquery::parsePlist(launchd_path, tree);
  ASSERT_TRUE(status.ok());

  // Parse the contents into a launchd table row.
  QueryData results;
  genLaunchdItem(tree, launchd_path, results);
  ASSERT_EQ(results.size(), 1U);

  Row expected = {
      {"path", (getTestConfigDirectory() / "test_launchd.plist").string()},
      {"name", "test_launchd.plist"},
      {"label", "com.apple.mDNSResponder"},
      {"run_at_load", ""},
      {"keep_alive", ""},
      {"on_demand", "0"},
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

  // We could compare the entire map, but iterating the columns will produce
  // better error text as most likely parsing for a certain column/type changed.
  for (const auto& column : expected) {
    EXPECT_EQ(results[0][column.first], column.second);
  }
}
}
}
