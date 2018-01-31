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

#include "osquery/tests/test_util.h"

namespace fs = boost::filesystem;

namespace osquery {
namespace tables {

void genLoginItems(const fs::path& sipath, QueryData& results);

class StartupItemsTests : public testing::Test {};

TEST_F(StartupItemsTests, test_parse_startup_items) {
  auto si_path = kTestDataPath + "test_startup_items.plist";

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
