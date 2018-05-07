
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

#include "osquery/dispatcher/task_schedule.h"

namespace osquery {

void TaskSchedule::add(TaskImplementation impl, UnixTime first_run_time) {
  task_heap_.emplace_back(std::move(impl), first_run_time);
  std::push_heap(task_heap_.begin(), task_heap_.end(), Task::comparator);
}

bool TaskSchedule::isEmpty() const {
  return task_heap_.empty();
}

TaskSchedule::UnixTime TaskSchedule::nextTimeToRun() const {
  return isEmpty() ? 0 : task_heap_.front().getNextTimeToRun();
}

void TaskSchedule::runNextNow() {
  if (!isEmpty()) {
    std::pop_heap(task_heap_.begin(), task_heap_.end(), Task::comparator);
    if (task_heap_.back().run()) {
      std::push_heap(task_heap_.begin(), task_heap_.end(), Task::comparator);
    } else {
      task_heap_.pop_back();
    }
  }
}

TaskSchedule::Task::Task(TaskImplementation impl, UnixTime first_run_time)
    : impl_(std::move(impl)), next_run_time_(first_run_time) {}

bool TaskSchedule::Task::run() {
  next_run_time_ = impl_(next_run_time_);
  return next_run_time_ != 0;
}

TaskSchedule::UnixTime TaskSchedule::Task::getNextTimeToRun() const
    noexcept {
  return next_run_time_;
}

bool TaskSchedule::Task::comparator(const Task& left, const Task& right) {
  return left.getNextTimeToRun() > right.getNextTimeToRun();
}

} // namespace osquery
