/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <gtest/gtest.h>

#include <osquery/utils/conversions/split.h>

namespace osquery {

class ConversionsTests : public testing::Test {};

struct SplitStringTestData {
  std::string test_string;
  std::string delim;
  std::vector<std::string> test_vector;
};

std::vector<SplitStringTestData> generateSplitStringTestData() {
  SplitStringTestData s1;
  s1.test_string = "a b\tc";
  s1.test_vector = {"a", "b", "c"};

  SplitStringTestData s2;
  s2.test_string = " a b   c";
  s2.test_vector = {"a", "b", "c"};

  SplitStringTestData s3;
  s3.test_string = "  a     b   c";
  s3.test_vector = {"a", "b", "c"};

  return {s1, s2, s3};
}

TEST_F(ConversionsTests, test_split) {
  for (const auto& i : generateSplitStringTestData()) {
    EXPECT_EQ(split(i.test_string), i.test_vector);
  }
}

TEST_F(ConversionsTests, test_split_occurrences) {
  std::string content = "T: 'S:S'";
  std::vector<std::string> expected = {
      "T", "'S:S'",
  };
  EXPECT_EQ(split(content, ':', 1), expected);
}

} // namespace osquery
