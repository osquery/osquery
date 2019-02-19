/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include "status.h"

#include <cassert>

namespace osquery {

constexpr int Status::kSuccessCode;

Status Status::failure(int code, std::string message) {
  assert(code != Status::kSuccessCode &&
         "Using 'failure' to create Status object with a kSuccessCode");
  return Status(code, std::move(message));
}

::std::ostream& operator<<(::std::ostream& os, const Status& s) {
  return os << "Status(" << s.getCode() << R"(, ")" << s.getMessage()
            << R"("))";
}

} // namespace osquery
