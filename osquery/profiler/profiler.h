/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#pragma once

#include <memory>
#include <string>

namespace osquery {

class CodeProfiler final {
 public:
  CodeProfiler(std::string name);

  ~CodeProfiler();

  void appendName(const std::string& appendName) {
    name_ += appendName;
  }

 private:
  class CodeProfilerData;

  std::string name_;
  std::unique_ptr<CodeProfilerData> code_profiler_data_;
};

} // namespace osquery
