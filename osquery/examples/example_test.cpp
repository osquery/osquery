// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>

namespace osquery {
namespace example {

class ExampleTests : public testing::Test {};

TEST_F(ExampleTests, test_plugin) {
  EXPECT_TRUE(1 == 1);
}
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
