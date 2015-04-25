/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/logger.h>

#include "osquery/core/test_util.h"

namespace osquery {

class TextTests : public testing::Test {};

TEST_F(TextTests, test_split) {
  for (const auto& i : generateSplitStringTestData()) {
    EXPECT_EQ(split(i.test_string), i.test_vector);
  }
}

TEST_F(TextTests, test_join) {
  std::vector<std::string> content = {
      "one", "two", "three",
  };
  EXPECT_EQ(join(content, ", "), "one, two, three");
}

TEST_F(TextTests, test_split_occurences) {
  std::string content = "T: 'S:S'";
  std::vector<std::string> expected = {
      "T", "'S:S'",
  };
  EXPECT_EQ(split(content, ":", 1), expected);
}
}

int main(int argc, char* argv[]) {
  google::InitGoogleLogging(argv[0]);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
