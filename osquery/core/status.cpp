/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/logger.h>
#include <osquery/status.h>

namespace osquery {

constexpr int Status::success_code;

Status Status::failure(int code, std::string message) {
  if (code == Status::success_code) {
    LOG(ERROR) << "Using Status::failure to create Status object with "
                  "a Status::success_code";
  }
  return Status(code, std::move(message));
}

} // namespace osquery
