/*
 *  Copyright (c) 2015, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/config.h>
#include <osquery/tables.h>

namespace osquery {
namespace tables {

/**
 * @brief A simple ConfigParserPlugin for a "pack" dictionary key.
 *
 */
class QueryPackConfigParserPlugin : public ConfigParserPlugin {
 public:
  /// Request "pack" top level key.
  std::vector<std::string> keys() { return {"pack"}; }

 private:
  /// Store the signatures and file_paths and compile the rules.
  Status update(const std::map<std::string, ConfigTree>& config);
};

}
}
