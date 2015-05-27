/*
 *  Copyright (c) 2015, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <osquery/config.h>
#include <osquery/tables.h>

namespace osquery {

/**
 * @brief A simple ConfigParserPlugin for a "packs" dictionary key.
 *
 */
class QueryPackConfigParserPlugin : public ConfigParserPlugin {
 public:
  /// Request "packs" top level key.
  std::vector<std::string> keys() { return {"packs"}; }

 private:
  /// Store the signatures and file_paths and compile the rules.
  Status update(const ConfigTreeMap& config);
};
}
