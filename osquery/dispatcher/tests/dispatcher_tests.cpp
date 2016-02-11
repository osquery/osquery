/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/make_shared.hpp>

#include <gtest/gtest.h>

#include "osquery/dispatcher/dispatcher.h"

namespace osquery {

class DispatcherTests : public testing::Test {};

TEST_F(DispatcherTests, test_singleton) {
  auto& one = Dispatcher::instance();
  auto& two = Dispatcher::instance();
  EXPECT_EQ(one.getThreadManager().get(), two.getThreadManager().get());
}

class TestRunnable : public InternalRunnable {
 public:
  int* i;
  explicit TestRunnable(int* i) : i(i) {}
  virtual void start() { ++*i; }
};

TEST_F(DispatcherTests, test_add_work) {
  auto& dispatcher = Dispatcher::instance();
  int base = 5;
  int repetitions = 1;

  int i = base;
  for (int c = 0; c < repetitions; ++c) {
    dispatcher.add(OSQUERY_THRIFT_POINTER::make_shared<TestRunnable>(&i));
  }
  while (dispatcher.totalTaskCount() > 0) {
  }

  EXPECT_EQ(i, base + repetitions);
}
}
