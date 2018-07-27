/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <CoreServices/CoreServices.h>

#include <gtest/gtest.h>

#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/tests/test_util.h"

namespace osquery {
namespace tables {

typedef std::pair<MDQueryRef, std::string> NamedQuery;

std::vector<NamedQuery> genSpotlightSearches(
    const std::set<std::string>& queries);
Status waitForSpotlight(const std::vector<NamedQuery>& queries);
void genResults(const std::vector<NamedQuery>& queries, QueryData& results);

class MdFindTests : public testing::Test {};

TEST_F(MdFindTests, test_mdfind_finds_osquery) {
  auto queries = genSpotlightSearches({"kMDItemTextContent == \"osquery\""});
  auto s = waitForSpotlight(queries);
  EXPECT_TRUE(s.ok());
  QueryData results;
  genResults(queries, results);

  EXPECT_GE(results.size(), 0UL);

  for (const auto& row : results) {
    EXPECT_EQ(row.count("path"), 1);
    EXPECT_EQ(row.count("query"), 1);
  }
}
} // namespace tables
} // namespace osquery
