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

class ScheduledTaskQueue {
public:
  using UnixTime = decltype(getUnixTime());
  using TaskImplementation = std::function<UnixTime(UnixTime startTime)>;

  /**
  * Add the task to the queue
  */
  void add(
    TaskImplementation task,
    UnixTime firstRunTime = 0
  );

  /**
  * Is task queue empty?
  */
  bool isEmpty() const;

  /**
  * Time to wait in seconds, to get task from the head of the queue ready
  * TODO: it good to use std::chrono::duration here one day
  */
  UnixTime timeToWait() const;

  /**
  * Run task from the head of the queue and reinsert it into the queue
  * if the return value is not zero.
  * Be careful, it will be runned regardless of required run time. Be sure that
  * return value of timeToWait() is zero. It works that way because we need to
  * avoid spin lock here.
  */
  void runOne();

private:
  class Task {
  public:
    explicit Task(
      TaskImplementation impl,
      UnixTime firstRunTime
    );

    Task(const Task&) = delete;
    Task& operator=(const Task&) = delete;

    Task(Task&&) = default;
    Task& operator=(Task&&) = default;

    bool run();

    UnixTime getNextRunTime() const noexcept;

    UnixTime getTimeToWait() const;

    static bool comparator(const Task& left, const Task& right);

  private:
    TaskImplementation impl_;
    UnixTime nextRunTime_;
  };

private:
  std::vector<Task> taskQueue_;
};

}
