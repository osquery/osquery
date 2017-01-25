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

#include "osquery/config/parsers/prometheus_targets.h"

namespace osquery {

std::vector<std::string> PrometheusMetricsConfigParserPlugin::keys() const {
  return {kConfigParserRootKey};
}

Status PrometheusMetricsConfigParserPlugin::setUp() {
  data_.put_child(kConfigParserRootKey, boost::property_tree::ptree());
  return Status(0, "OK");
}

Status PrometheusMetricsConfigParserPlugin::update(const std::string& source,
                                                   const ParserConfig& config) {
  if (config.count(kConfigParserRootKey) > 0) {
    data_ = boost::property_tree::ptree();
    data_.put_child(kConfigParserRootKey, config.at(kConfigParserRootKey));
  }

  return Status(0, "OK");
}

REGISTER_INTERNAL(PrometheusMetricsConfigParserPlugin,
                  "config_parser",
                  "prometheus_targets");
}
