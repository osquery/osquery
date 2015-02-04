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

#include <osquery/dispatcher.h>

namespace osquery {

class DispatcherTests : public testing::Test {};

TEST_F(DispatcherTests, test_singleton) {
  auto& one = Dispatcher::getInstance();
  auto& two = Dispatcher::getInstance();
  EXPECT_EQ(one.getThreadManager().get(), two.getThreadManager().get());
}

class TestRunnable : public InternalRunnable {
 public:
  int* i;
  TestRunnable(int* i) : i(i) {}
  virtual void run() { ++*i; }
};

TEST_F(DispatcherTests, test_add_work) {
  auto& dispatcher = Dispatcher::getInstance();
  int base = 5;
  int repetitions = 1;

  int i = base;
  for (int c = 0; c < repetitions; ++c) {
    dispatcher.add(std::make_shared<TestRunnable>(&i));
  }
  while (dispatcher.totalTaskCount() > 0) {
  }

  EXPECT_EQ(i, base + repetitions);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
