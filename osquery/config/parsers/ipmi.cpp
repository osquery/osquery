/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <iostream>

#include <osquery/config.h>
#include <osquery/logger.h>

#include "osquery/config/parsers/ipmi.h"

namespace osquery {

std::vector<std::string> IPMIConfigParserPlugin::keys() const {
  return {kIPMIConfigParserRootKey};
}

Status IPMIConfigParserPlugin::setUp() {
  data_.put_child(kIPMIConfigParserRootKey, boost::property_tree::ptree());
  return Status(0, "OK");
}

Status IPMIConfigParserPlugin::update(const std::string& source,
                                      const ParserConfig& config) {
  if (config.count(kIPMIConfigParserRootKey) > 0) {
    data_ = boost::property_tree::ptree();
    data_.put_child(kIPMIConfigParserRootKey,
                    config.at(kIPMIConfigParserRootKey));
  }

  return Status(0, "OK");
}

REGISTER_INTERNAL(IPMIConfigParserPlugin, "config_parser", "ipmi");
} // namespace osquery
