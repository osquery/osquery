/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <iostream>

#include <osquery/config/config.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry_factory.h>
#include <plugins/config/parsers/prometheus_targets.h>

namespace osquery {

const std::string kPrometheusParserRootKey("prometheus_targets");

std::vector<std::string> PrometheusMetricsConfigParserPlugin::keys() const {
  return {kPrometheusParserRootKey};
}

Status PrometheusMetricsConfigParserPlugin::update(const std::string& source,
                                                   const ParserConfig& config) {
  auto prometheus_targets = config.find(kPrometheusParserRootKey);
  if (prometheus_targets != config.end()) {
    auto doc = JSON::newObject();
    auto obj = doc.getObject();
    doc.copyFrom(prometheus_targets->second.doc(), obj);
    doc.add(kPrometheusParserRootKey, obj);
    data_ = std::move(doc);
  }

  return Status();
}

REGISTER_INTERNAL(PrometheusMetricsConfigParserPlugin,
                  "config_parser",
                  "prometheus_targets");
}
