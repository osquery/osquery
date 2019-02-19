/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <initializer_list>
#include <memory>
#include <string>
#include <vector>

#include <osquery/numeric_monitoring.h>

namespace osquery {

class CodeProfiler final {
 public:
  CodeProfiler(const std::initializer_list<std::string>& names);

  ~CodeProfiler();

 private:
  class CodeProfilerData;

  const std::vector<std::string> names_;
  const std::unique_ptr<CodeProfilerData> code_profiler_data_;
};

} // namespace osquery
