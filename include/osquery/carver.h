/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <set>

#include <osquery/dispatcher.h>

namespace osquery {

class Carver : public InternalRunnable {
 public:
  Carver(const std::set<std::string>& paths);
  void start();

private:
  std::set<std::string> carvePaths_;
};
}
