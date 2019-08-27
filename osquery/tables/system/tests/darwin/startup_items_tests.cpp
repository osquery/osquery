/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <gtest/gtest.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/core/sql/query_data.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger.h>

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

void genLoginItems(const fs::path& sipath, QueryData& results);

class StartupItemsTests : public testing::Test {};

TEST_F(StartupItemsTests, test_parse_startup_items) {
  auto si_path = getTestConfigDirectory() / "test_startup_items.plist";

  // Parse the contents into a launchd table row.
  QueryData results;
  genLoginItems(si_path, results);
  ASSERT_EQ(results.size(), 2U);

  EXPECT_EQ("/Applications/iTunes.app/Contents/MacOS/iTunesHelper.app/",
            results[0]["path"]);

  // The second entry cannot be parsed with bookmark resolution.
  EXPECT_EQ("/private/tmp/this_does_not_exist", results[1]["path"]);
}
} // namespace tables
} // namespace osquery
