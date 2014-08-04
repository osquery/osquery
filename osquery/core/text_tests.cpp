// Copyright 2004-present Facebook. All Rights Reserved.

#include "osquery/core.h"

#include <gtest/gtest.h>
#include <glog/logging.h>

#include "osquery/core/test_util.h"

namespace osquery { namespace core {

class TextTests : public testing::Test {};

TEST_F(TextTests, test_split_string) {
  for (auto i : generateSplitStringTestData()) {
    EXPECT_EQ(splitString(i.test_string, i.delim), i.test_vector);
  }
}

TEST_F(TextTests, test_join_string) {
  for (auto i : generateJoinStringTestData()) {
    EXPECT_EQ(joinString(i.test_vector, i.delim), i.test_string);
  }
}

}}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
