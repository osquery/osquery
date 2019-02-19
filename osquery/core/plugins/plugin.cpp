/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include "plugin.h"

namespace osquery {

void Plugin::setName(const std::string& name) {
  if (!name_.empty() && name != name_) {
    std::string error = "Cannot rename plugin " + name_ + " to " + name;
    throw std::runtime_error(error);
  }

  name_ = name;
}

PluginResponse tableRowsToPluginResponse(const TableRows& rows) {
  PluginResponse result;
  for (const auto& row : rows) {
    result.push_back(static_cast<Row>(*row));
  }
  return result;
}

} // namespace osquery
