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

class SplitConversionsTests : public testing::Test {};

struct SplitStringTestData {
  std::string test_string;
  std::string delim;
  std::vector<std::string> test_vector;
};

std::vector<SplitStringTestData> generateVSplitStringTestData() {
  SplitStringTestData s1;
  s1.test_string = " a b   c";
  s1.test_vector = {"a", "b", "c"};
  s1.delim = " ";

  SplitStringTestData s2;
  s2.test_string = "  a     b   c";
  s2.test_vector = {"a", "b", "c"};
  s2.delim = " ";

  SplitStringTestData s3;
  s3.delim = " ";

  SplitStringTestData s4;
  s4.test_string = "a b c ";
  s4.test_vector = {"a", "b", "c"};
  s4.delim = " ";

  SplitStringTestData s5;
  s5.test_string = "abc";
  s5.test_vector = {"abc"};
  s5.delim = " ";

  SplitStringTestData s6;
  s6.test_string = "  ";
  s6.delim = " ";

  SplitStringTestData s7;
  s7.test_string = "a,b,c";
  s7.test_vector = {"a", "b", "c"};
  s7.delim = ",";

  SplitStringTestData s8;
  s8.test_string = " ,a,b,c";
  s8.test_vector = {" ", "a", "b", "c"};
  s8.delim = ",";

  return {s1, s2, s3, s4, s5, s6, s7, s8};
}

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

  SplitStringTestData s4;

  SplitStringTestData s5;
  s5.test_string = "a b c ";
  s5.test_vector = {"a", "b", "c"};

  SplitStringTestData s6;
  s6.test_string = "abc";
  s6.test_vector = {"abc"};

  SplitStringTestData s7;
  s7.test_string = "  ";

  return {s1, s2, s3, s4, s5, s6, s7};
}

TEST_F(SplitConversionsTests, test_split) {
  for (const auto& i : generateSplitStringTestData()) {
    EXPECT_EQ(split(i.test_string), i.test_vector);
  }
}

TEST_F(SplitConversionsTests, test_vplit) {
  auto test_data = generateVSplitStringTestData();
  for (auto it = test_data.begin() + 1; it != test_data.end(); ++it) {
    auto splits =
        vsplit(it->test_string, it->delim.empty() ? '\0' : it->delim[0]);

    ASSERT_EQ(splits.size(), it->test_vector.size())
        << "Failed to split " << it->test_string;

    for (std::size_t i = 0; i < splits.size(); ++i) {
      EXPECT_EQ(splits[i], it->test_vector[i]);
    }
  }
}

TEST_F(SplitConversionsTests, test_split_occurrences) {
  std::string content = "T: 'S:S'";
  std::vector<std::string> expected = {
      "T",
      "'S:S'",
  };
  EXPECT_EQ(split(content, ':', 1), expected);
}

} // namespace osquery
