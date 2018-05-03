
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <algorithm>
#include <limits>

#include "osquery/dispatcher/scheduled_tasks_queue.h"

namespace osquery {

void ScheduledTaskQueue::add(TaskImplementation impl, UnixTime firstRunTime) {
  taskQueue_.emplace_back(std::move(impl), firstRunTime);
  std::push_heap(taskQueue_.begin(), taskQueue_.end(), Task::comparator);
}

bool ScheduledTaskQueue::isEmpty() const {
  return taskQueue_.empty();
}

ScheduledTaskQueue::UnixTime ScheduledTaskQueue::timeToWait() const {
  return isEmpty() ? 0 : taskQueue_.front().getTimeToWait();
}

void ScheduledTaskQueue::runOne() {
  if (not isEmpty()) {
    std::pop_heap(taskQueue_.begin(), taskQueue_.end(), Task::comparator);
    if (taskQueue_.back().run()) {
      std::push_heap(taskQueue_.begin(), taskQueue_.end(), Task::comparator);
    } else {
      taskQueue_.pop_back();
    }
  }
}

ScheduledTaskQueue::Task::Task(TaskImplementation impl, UnixTime firstRunTime)
    : impl_(std::move(impl)), nextRunTime_(firstRunTime) {}

bool ScheduledTaskQueue::Task::run() {
  auto startTime = osquery::getUnixTime();
  nextRunTime_ = impl_(startTime);
  if (nextRunTime_ == 0) {
    nextRunTime_ = std::numeric_limits<UnixTime>::max();
    return false;
  }
  return true;
}

ScheduledTaskQueue::UnixTime ScheduledTaskQueue::Task::getNextRunTime() const
    noexcept {
  return nextRunTime_;
}

ScheduledTaskQueue::UnixTime ScheduledTaskQueue::Task::getTimeToWait() const {
  const auto now = osquery::getUnixTime();
  return now < nextRunTime_ ? nextRunTime_ - now : UnixTime{0};
}

bool ScheduledTaskQueue::Task::comparator(const Task& left, const Task& right) {
  return left.getNextRunTime() > right.getNextRunTime();
}

} // namespace osquery
