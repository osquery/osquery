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
#include <string>
#include <vector>

#include <osquery/config.h>
#include <osquery/logger.h>

#include <osquery/tables/applications/posix/prometheus_metrics_utils.h>

namespace osquery {

Status PrometheusMetricsConfigParserPlugin::setUp() {
  data_.put_child(configParserRootKey, pt::ptree());
  return Status(0, "OK");
}

Status PrometheusMetricsConfigParserPlugin::update(const std::string& source,
                                                   const ParserConfig& config) {
  if (config.count(configParserRootKey) > 0) {
    data_ = pt::ptree();
    data_.put_child(configParserRootKey, config.at(configParserRootKey));
  }

  return Status(0, "OK");
}

REGISTER(PrometheusMetricsConfigParserPlugin,
         "config_parser",
         "prometheus_targets");
}
