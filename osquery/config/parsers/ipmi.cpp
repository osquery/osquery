/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/config.h>
#include <osquery/logger.h>

#include "osquery/config/parsers/ipmi.h"

namespace osquery {

const std::string kIPMIConfigParserRootKey("ipmi");

std::vector<std::string> IPMIConfigParserPlugin::keys() const {
  return {kIPMIConfigParserRootKey};
}

Status IPMIConfigParserPlugin::update(const std::string& source,
                                      const ParserConfig& config) {
  auto fields = config.find(kIPMIConfigParserRootKey);
  if (fields != config.end()) {
    auto obj = data_.getObject();
    data_.copyFrom(fields->second.doc(), obj);
    data_.add(kIPMIConfigParserRootKey, obj);
  }

  return Status(0, "OK");
}

REGISTER_INTERNAL(IPMIConfigParserPlugin, "config_parser", "ipmi");
} // namespace osquery
