/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <chrono>
#include <gflags/gflags.h>
#include <memory>
#include <vector>

#include <aws/kinesis/KinesisClient.h>
#include <aws/kinesis/model/PutRecordsRequestEntry.h>

#include <osquery/core.h>
#include <osquery/dispatcher.h>
#include <osquery/plugins/logger.h>
#include <plugins/logger/cached_logger.h>

namespace osquery {

class KinesisLoggerPlugin : public CachedLoggerPlugin {
 public:
  KinesisLoggerPlugin() : CachedLoggerPlugin() {}

  Status setUp() override;

  bool usesLogStatus() override {
    return true;
  }

  void init(const std::string& name,
            const std::vector<StatusLogLine>& log) override;

 private:
};

} // namespace osquery
