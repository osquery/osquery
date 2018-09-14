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

#include <boost/format.hpp>

#include <osquery/killswitch.h>
#include <osquery/numeric_monitoring.h>
#include <osquery/profiler/profiler.h>

namespace osquery {

class CodeProfiler::CodeProfilerData {
 public:
  CodeProfilerData() : wall_time_(std::chrono::steady_clock::now()) {}

  const std::chrono::time_point<std::chrono::steady_clock>& getWallTime() {
    return wall_time_;
  }

 private:
  std::chrono::time_point<std::chrono::steady_clock> wall_time_;
};

CodeProfiler::CodeProfiler(std::string name)
    : name_(name), code_profiler_data_(new CodeProfilerData()) {}

CodeProfiler::~CodeProfiler() {
  if (Killswitch::get().isWindowsProfilingEnabled()) {
    CodeProfilerData code_profiler_data_end;

    const auto query_duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            code_profiler_data_end.getWallTime() -
            code_profiler_data_->getWallTime());

    monitoring::record(name_ + ".time.wall.millis",
                       query_duration.count(),
                       monitoring::PreAggregationType::Min);
  }
}

} // namespace osquery
