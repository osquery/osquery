/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <initializer_list>
#include <memory>
#include <string>
#include <vector>

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
