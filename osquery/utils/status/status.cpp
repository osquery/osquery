/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
