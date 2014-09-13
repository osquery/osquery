// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>

#include "osquery/dispatcher.h"

namespace osquery {

class DispatcherTests : public testing::Test {};

TEST_F(DispatcherTests, test_singleton) {
  auto one = Dispatcher::getInstance();
  auto two = Dispatcher::getInstance();
  EXPECT_EQ(one->getThreadManager().get(), two->getThreadManager().get());
}

class TestRunnable : public apache::thrift::concurrency::Runnable {
 public:
  int* i;
  TestRunnable(int* i) : i(i) {}
  virtual void run() { ++*i; }
};

TEST_F(DispatcherTests, test_add_work) {
  auto d = Dispatcher::getInstance();
  int base = 5;
  int repetitions = 1;

  int i = base;
  for (int c = 0; c < repetitions; ++c) {
    d->add(std::make_shared<TestRunnable>(&i));
  }
  while (d->totalTaskCount() > 0) {
  }

  EXPECT_EQ(i, base + repetitions);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
