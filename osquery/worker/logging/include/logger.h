/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <string>

namespace osquery {
class Logger {
 public:
  virtual ~Logger() = default;
  virtual void log(int severity, const std::string& message) = 0;
  virtual void vlog(int severity, const std::string& message) = 0;
};
} // namespace osquery
