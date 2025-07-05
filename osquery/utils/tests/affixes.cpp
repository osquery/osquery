/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/utils/affixes.h>

namespace osquery {

class AffixesTests : public testing::Test {};

TEST_F(AffixesTests, test_affixes) {
  std::vector<std::string> prefixes = {"query.", "cache.", "prefix"};
  std::vector<std::string> suffixes = {"epoch", "counter", "suffix"};

  bool result = hasAnyPrefix("query.name", prefixes);
  EXPECT_TRUE(result);

  result = hasAnyPrefix("query.", prefixes);
  EXPECT_TRUE(result);

  result = hasAnyPrefix("cache.name", prefixes);
  EXPECT_TRUE(result);

  result = hasAnyPrefix("othername", prefixes);
  EXPECT_FALSE(result);

  result = hasAnyPrefix("cache", prefixes);
  EXPECT_FALSE(result);

  result = hasAnyPrefix("pre", prefixes);
  EXPECT_FALSE(result);

  result = hasAnySuffix("nameepoch", suffixes);
  EXPECT_TRUE(result);

  result = hasAnySuffix("namecounter", suffixes);
  EXPECT_TRUE(result);

  result = hasAnySuffix("counter", suffixes);
  EXPECT_TRUE(result);

  result = hasAnySuffix("nter", suffixes);
  EXPECT_FALSE(result);

  result = hasAnySuffix("nameother", suffixes);
  EXPECT_FALSE(result);

  result = hasAnySuffix("fix", suffixes);
  EXPECT_FALSE(result);

  result = hasAnySuffix("", suffixes);
  EXPECT_FALSE(result);
}

} // namespace osquery
