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
