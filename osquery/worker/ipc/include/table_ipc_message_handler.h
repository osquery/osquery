/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#pragma once

#include <string>

#include <osquery/tables.h>
#include <osquery/utils/status/status.h>

#include <osquery/worker/logging/glog_logger_types.h>

namespace osquery {
class TableIPCMessageHandler {
 public:
  virtual ~TableIPCMessageHandler() {}
  virtual Status handleLog(GLOGLogType log_type,
                           int priority,
                           const std::string& message) = 0;
  virtual Status handleJob(QueryContext& context) = 0;
};

} // namespace osquery
