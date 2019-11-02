/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/config/config_parser_plugin.h>
#include <osquery/registry.h>

namespace osquery {

/**
 * @brief ConfigParser plugin registry.
 *
 * This creates an osquery registry for "config_parser" which may implement
 * ConfigParserPlugin. A ConfigParserPlugin should not export any call actions
 * but rather have a simple property tree-accessor API through Config.
 */
CREATE_LAZY_REGISTRY(ConfigParserPlugin, "config_parser");

void ConfigParserPlugin::reset() {
  // Resets will clear all top-level keys from the parser's data store.
  for (auto& category : data_.doc().GetObject()) {
    auto obj = data_.getObject();
    data_.add(category.name.GetString(), obj, data_.doc());
  }
}

Status ConfigParserPlugin::setUp() {
  for (const auto& key : keys()) {
    auto obj = data_.getObject();
    data_.add(key, obj);
  }
  return Status::success();
}

} // namespace osquery
