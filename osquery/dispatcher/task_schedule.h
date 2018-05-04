/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <functional>
#include <vector>

#include <osquery/system.h>

namespace osquery {

class TaskSchedule {
 public:
  /**
   * @brief Type alias for a time
   * TODO: it would be good to use std::chrono::time_point here one day
   */
  using UnixTime = decltype(getUnixTime());

  /**
   * @brief The implementation of task in form of function
   *
   * @param scheduled_time The scheduled time of this particular run of task
   * @return The time for the next run or 0 if the task shouldn not be
   * scheduled again
   */
  using TaskImplementation = std::function<UnixTime(UnixTime scheduled_time)>;

  /**
   * @brief Add the task to the queue
   * @param task The task implementation
   * @param first_time_to_run The time of first run. It can be less then current
   * time, task will be runned anyway. The order of first runs depends on this
   * time, tasks with smallest time have highest priority. For two tasks with
   * equal first run time the order of first run in undefined.
   */
  void add(TaskImplementation task, UnixTime first_time_to_run);

  /**
   * @return True, if task queue is empty
   */
  bool isEmpty() const;

  /**
   * @return The time to run the task from the head of the queue
   */
  UnixTime nextTimeToRun() const;

  /**
   * @brief Run task from the head of the queue independent of the required run
   * time. And reinsert it into the queue if the return value is not zero.
   */
  void runNextNow();

 private:
  class Task {
   public:
    explicit Task(TaskImplementation impl, UnixTime first_time_to_run);

    Task(const Task&) = delete;
    Task& operator=(const Task&) = delete;

    Task(Task&&) = default;
    Task& operator=(Task&&) = default;

    bool run();

    UnixTime getNextTimeToRun() const noexcept;

    static bool comparator(const Task& left, const Task& right);

   private:
    TaskImplementation impl_;
    UnixTime next_run_time_;
  };

 private:
  std::vector<Task> task_heap_;
};

} // namespace osquery
