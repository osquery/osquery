// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"

#include <gtest/gtest.h>
#include <glog/logging.h>

#include "osquery/core/test_util.h"

namespace osquery { namespace core {

class TextTests : public testing::Test {};

TEST_F(TextTests, test_split) {
  for (auto i : generateSplitStringTestData()) {
    EXPECT_EQ(split(i.test_string), i.test_vector);
  }
}

TEST_F(TextTests, test_join_string) {
  for (auto i : generateJoinStringTestData()) {
    EXPECT_EQ(join(i.test_vector, i.delim), i.test_string);
  }
}

TEST_F(TextTests, test_ltrim) {
  std::string s = " foo ";
  EXPECT_EQ(ltrim(s), "foo ");
}

TEST_F(TextTests, test_rtrim) {
  std::string s = " foo ";
  EXPECT_EQ(rtrim(s), " foo");
}

TEST_F(TextTests, test_trim) {
  std::string s = " foo ";
  EXPECT_EQ(trim(s), "foo");
}

}}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
