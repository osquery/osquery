/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <chrono>
#include <iostream>
#include <thread>

#include <gtest/gtest.h>

#include <osquery/config.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/dispatcher/task_schedule.h"

namespace osquery {

DECLARE_bool(disable_logging);

class TaskScheduleTests : public testing::Test {
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

TEST_F(TaskScheduleTests, run_for_the_one_time) {
  auto tasks = TaskSchedule{};
  auto counter = int{0};
  tasks.add(
      [&counter](const auto scheduled_time) {
        ++counter;
        return 0;
      },
      0);
  while (!tasks.isEmpty()) {
    auto next_time_to_run = tasks.nextTimeToRun();
    auto now = getUnixTime();
    if (now < next_time_to_run) {
      std::this_thread::sleep_for(std::chrono::seconds{next_time_to_run - now});
    } else {
      tasks.runNextNow();
    }
  }
  EXPECT_EQ(counter, 1);
}

TEST_F(TaskScheduleTests, first_start_priority) {
  auto tasks = TaskSchedule{};
  auto counter = int{0};
  tasks.add(
      [&counter](const auto scheduled_time) {
        ++counter;
        return 0;
      },
      10);
  tasks.add(
      [&counter](const auto scheduled_time) {
        counter *= 2;
        return 0;
      },
      100);
  while (!tasks.isEmpty()) {
    auto next_time_to_run = tasks.nextTimeToRun();
    auto now = getUnixTime();
    if (now < next_time_to_run) {
      std::this_thread::sleep_for(std::chrono::seconds{next_time_to_run - now});
    } else {
      tasks.runNextNow();
    }
  }
  EXPECT_EQ(counter, 2);
}

TEST_F(TaskScheduleTests, one_shot_task) {
  auto tasks = TaskSchedule{};
  auto one_shot_counter = int{0};
  auto counter = int{0};
  tasks.add([&counter](const auto scheduled_time) {
    ++counter;
    return 1;
  });
  tasks.add([&one_shot_counter](const auto scheduled_time) {
    ++one_shot_counter;
    return 0;
  });
  for (int i = 0; i < 10 && !tasks.isEmpty(); ++i) {
    auto next_time_to_run = tasks.nextTimeToRun();
    auto now = getUnixTime();
    if (now < next_time_to_run) {
      std::this_thread::sleep_for(std::chrono::seconds{next_time_to_run - now});
    } else {
      tasks.runNextNow();
    }
  }
  EXPECT_EQ(one_shot_counter, 1);
  EXPECT_EQ(counter, 9);
}

TEST_F(TaskScheduleTests, zero_time_to_wait) {
  auto tasks = TaskSchedule{};
  tasks.add([](const auto scheduled_time) { return scheduled_time; });
  auto sum_waiting_time = decltype(tasks.nextTimeToRun()){0};
  for (int i = 0; i < 10 && !tasks.isEmpty(); ++i) {
    auto next_time_to_run = tasks.nextTimeToRun();
    auto now = getUnixTime();
    if (now < next_time_to_run) {
      auto time_to_wait = next_time_to_run - now;
      sum_waiting_time += time_to_wait;
      std::this_thread::sleep_for(std::chrono::seconds{time_to_wait});
    } else {
      tasks.runNextNow();
    }
  }
  EXPECT_EQ(sum_waiting_time, 0u);
}

TEST_F(TaskScheduleTests, run_next_regardless_of_time) {
  auto tasks = TaskSchedule{};
  auto counter = int{0};
  tasks.add([&counter](const auto scheduled_time) {
    ++counter;
    return scheduled_time + 10;
  });
  for (int i = 0; i < 10 && !tasks.isEmpty(); ++i) {
    tasks.runNextNow();
  }
  EXPECT_EQ(counter, 10);
}

} // namespace osquery
