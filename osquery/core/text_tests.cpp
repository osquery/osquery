// Copyright 2004-present Facebook. All Rights Reserved.

#include <osquery/core.h>

#include <gtest/gtest.h>
#include <glog/logging.h>

#include "osquery/core/test_util.h"

namespace osquery {
namespace core {

class TextTests : public testing::Test {};

TEST_F(TextTests, test_split) {
  for (const auto& i : generateSplitStringTestData()) {
    EXPECT_EQ(split(i.test_string), i.test_vector);
  }
}
}
}

int main(int argc, char* argv[]) {
  google::InitGoogleLogging(argv[0]);
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
