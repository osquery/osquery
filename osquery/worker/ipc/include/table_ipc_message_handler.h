/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <string>

#include <osquery/core/tables.h>
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
