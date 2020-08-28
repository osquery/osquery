/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>

#include <boost/format.hpp>

#include <osquery/numeric_monitoring/numeric_monitoring.h>
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
  CodeProfilerData code_profiler_data_end;

  const auto query_duration =
      std::chrono::duration_cast<std::chrono::milliseconds>(
          code_profiler_data_end.getWallTime() -
          code_profiler_data_->getWallTime());

  record(names_, ".time.wall.millis", query_duration.count());
}
} // namespace osquery
