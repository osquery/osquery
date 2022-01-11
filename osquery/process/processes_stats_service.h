/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <osquery/process/processes_stats.h>

#include <cstdint>
#include <memory>
#include <unordered_map>

#include <osquery/dispatcher/dispatcher.h>

namespace osquery {

class ProcessesStatsService final : public InternalRunnable {
 public:
  ProcessesStatsService(std::shared_ptr<ProcessesStats> processes_stats);

 protected:
  void start();

 private:
  std::shared_ptr<ProcessesStats> processes_stats_;
};
} // namespace osquery
