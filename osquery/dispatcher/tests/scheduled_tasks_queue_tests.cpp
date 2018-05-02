/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iostream>
#include <chrono>
#include <thread>

#include <gtest/gtest.h>

#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/dispatcher/scheduled_tasks_queue.h"

namespace osquery {

DECLARE_bool(disable_logging);

class ScheduledTasksQueueTests : public testing::Test {
  void SetUp() override {
    logging_ = FLAGS_disable_logging;
    FLAGS_disable_logging = true;
  }

  void TearDown() override {
    FLAGS_disable_logging = logging_;
  }

 private:
  bool logging_{false};
};

TEST_F(ScheduledTasksQueueTests, run_for_the_one_time) {
  auto tasks = ScheduledTaskQueue{};
  auto counter = int{0};
  tasks.add([&counter](auto startTime){
    ++counter;
    return 0;
  }, 0);
  while (!tasks.isEmpty()) {
    auto toWaitInSeconds = tasks.timeToWait();
    if (toWaitInSeconds > 0) {
      std::this_thread::sleep_for(std::chrono::seconds{toWaitInSeconds});
    }
    tasks.runOne();
  }
  EXPECT_EQ(counter, 1);
}

TEST_F(ScheduledTasksQueueTests, first_start_priority) {
  auto tasks = ScheduledTaskQueue{};
  auto counter = int{0};
  tasks.add([&counter](auto startTime){
    ++counter;
    return 0;
  }, 10);
  tasks.add([&counter](auto startTime){
    counter *= 2;
    return 0;
  }, 100);
  while (!tasks.isEmpty()) {
    auto toWaitInSeconds = tasks.timeToWait();
    if (toWaitInSeconds > 0) {
      std::this_thread::sleep_for(std::chrono::seconds{toWaitInSeconds});
    }
    tasks.runOne();
  }
  EXPECT_EQ(counter, 2);
}

TEST_F(ScheduledTasksQueueTests, one_shot_task) {
  auto tasks = ScheduledTaskQueue{};
  auto oneShotCounter = int{0};
  auto counter = int{0};
  tasks.add([&counter](auto startTime){
    ++counter;
    return startTime;
  });
  tasks.add([&oneShotCounter](auto startTime){
    ++oneShotCounter;
    return 0;
  });
  for (int i = 0; i < 10 && !tasks.isEmpty(); ++i) {
    auto toWaitInSeconds = tasks.timeToWait();
    if (toWaitInSeconds > 0) {
      std::this_thread::sleep_for(std::chrono::seconds{toWaitInSeconds});
    }
    tasks.runOne();
  }
  EXPECT_EQ(oneShotCounter, 1);
  EXPECT_EQ(counter, 9);
}

TEST_F(ScheduledTasksQueueTests, zero_time_to_wait) {
  auto tasks = ScheduledTaskQueue{};
  tasks.add([](auto startTime){
    return startTime;
  });
  auto sumWaitingTime = decltype(tasks.timeToWait()){0};
  for (int i = 0; i < 10 && !tasks.isEmpty(); ++i) {
    auto toWaitInSeconds = tasks.timeToWait();
    sumWaitingTime += toWaitInSeconds;
    if (toWaitInSeconds > 0) {
      std::this_thread::sleep_for(std::chrono::seconds{toWaitInSeconds});
    }
    tasks.runOne();
  }
  EXPECT_EQ(sumWaitingTime, 0u);
}

TEST_F(ScheduledTasksQueueTests, run_one_regardless_of_time) {
  auto tasks = ScheduledTaskQueue{};
  auto counter = int{0};
  tasks.add([&counter](auto startTime){
    ++counter;
    return startTime + 10;
  });
  for (int i = 0; i < 10 && !tasks.isEmpty(); ++i) {
    tasks.runOne();
  }
  EXPECT_EQ(counter, 10);
}

}
