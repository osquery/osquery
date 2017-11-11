/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iostream>

#include <osquery/config.h>
#include <osquery/logger.h>

#include "osquery/config/parsers/prometheus_targets.h"

namespace osquery {

const std::string kPrometheusParserRootKey("prometheus_targets");

std::vector<std::string> PrometheusMetricsConfigParserPlugin::keys() const {
  return {kPrometheusParserRootKey};
}

Status PrometheusMetricsConfigParserPlugin::update(const std::string& source,
                                                   const ParserConfig& config) {
  if (config.count(kPrometheusParserRootKey) > 0) {
    auto obj = data_.getObject();
    obj.CopyFrom(config.at(kPrometheusParserRootKey).doc(),
                 data_.doc().GetAllocator());
    data_.add(kPrometheusParserRootKey, obj);
  }

  return Status();
}

REGISTER_INTERNAL(PrometheusMetricsConfigParserPlugin,
                  "config_parser",
                  "prometheus_targets");
}
