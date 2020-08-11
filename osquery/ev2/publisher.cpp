/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/ev2/publisher.h>

namespace osquery {
namespace ev2 {

Publisher::Publisher(std::string name) : name_(name) {}

const std::string& Publisher::name() const {
  return name_;
}

} // namespace ev2
} // namespace osquery
