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

#include <cassert>

namespace osquery {

constexpr int Status::kSuccessCode;

Status Status::failure(int code, std::string message) {
  assert(code != Status::kSuccessCode &&
         "Using 'failure' to create Status object with a kSuccessCode");
  return Status(code, std::move(message));
}

} // namespace osquery
