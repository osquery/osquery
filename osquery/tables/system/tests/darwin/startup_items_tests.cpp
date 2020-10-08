/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string.hpp>
#include <gtest/gtest.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/core/sql/query_data.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>

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

  EXPECT_TRUE(boost::starts_with(
      results[0]["path"],
      "/Applications/iTunes.app/Contents/MacOS/iTunesHelper.app"));

  // The second entry cannot be parsed with bookmark resolution.
  EXPECT_TRUE(boost::starts_with(results[1]["path"],
                                 "/private/tmp/this_does_not_exist"));
}
} // namespace tables
} // namespace osquery
