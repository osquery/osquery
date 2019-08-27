/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <chrono>

#include <boost/format.hpp>

#include <osquery/killswitch.h>
#include <osquery/numeric_monitoring.h>
#include <osquery/profiler/code_profiler.h>

namespace osquery {
namespace {

void record(const std::vector<std::string>& names,
            const std::string& metricName,
            monitoring::ValueType measurement) {
  for (const auto& name : names) {
    monitoring::record(name + "." + metricName,
                       measurement,
                       monitoring::PreAggregationType::None);
  }
}

} // namespace
class CodeProfiler::CodeProfilerData {
 public:
  CodeProfilerData() : wall_time_(std::chrono::steady_clock::now()) {}

  const std::chrono::time_point<std::chrono::steady_clock>& getWallTime() {
    return wall_time_;
  }

 private:
  std::chrono::time_point<std::chrono::steady_clock> wall_time_;
};

CodeProfiler::CodeProfiler(const std::initializer_list<std::string>& names)
    : names_(names), code_profiler_data_(new CodeProfilerData()) {}

CodeProfiler::~CodeProfiler() {
  if (Killswitch::get().isWindowsProfilingEnabled()) {
    CodeProfilerData code_profiler_data_end;

    const auto query_duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            code_profiler_data_end.getWallTime() -
            code_profiler_data_->getWallTime());

    record(names_, ".time.wall.millis", query_duration.count());
  }
}
} // namespace osquery
