/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <unordered_map>

#include <gtest/gtest.h>

#include <osquery/filesystem/fileops.h>

namespace osquery {
namespace {
class DarwinBsdFlags : public testing::Test {};

TEST_F(DarwinBsdFlags, testAllFlags) {
  auto flags = UF_NODUMP | UF_IMMUTABLE | UF_APPEND | UF_OPAQUE | UF_HIDDEN |
               SF_ARCHIVED | SF_IMMUTABLE | SF_APPEND;

  std::string expected_description =
      "NODUMP, UF_IMMUTABLE, UF_APPEND, OPAQUE, HIDDEN, ARCHIVED, "
      "SF_IMMUTABLE, SF_APPEND";

  // The function should return true when there are no undocumented bits
  // set inside the `flags` value
  std::string description;
  auto s = describeBSDFileFlags(description, flags);
  EXPECT_TRUE(s);

  EXPECT_EQ(description, expected_description);
}

TEST_F(DarwinBsdFlags, foreignFlags) {
  auto flags = UF_NODUMP | 0xFF000000U;
  std::string expected_description = "NODUMP, 0xff000000";

  // The function should return false when there are undocumented bits used
  // in the `flags` value
  std::string description;
  auto s = describeBSDFileFlags(description, flags);
  EXPECT_FALSE(s);

  EXPECT_EQ(description, expected_description);
}
} // namespace
} // namespace osquery
