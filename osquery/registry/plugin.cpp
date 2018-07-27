/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/plugin.h>

namespace osquery {
void Plugin::setName(const std::string& name) {
  if (!name_.empty() && name != name_) {
    std::string error = "Cannot rename plugin " + name_ + " to " + name;
    throw std::runtime_error(error);
  }

  name_ = name;
}

} // namespace osquery
