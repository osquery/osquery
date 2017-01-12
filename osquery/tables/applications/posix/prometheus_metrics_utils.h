/*
 *  Copyright (c) 2015, Welsey Shields
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <string>
#include <vector>

#include <osquery/config.h>

namespace pt = boost::property_tree;

namespace osquery {

const std::string configParserRootKey("prometheus_targets");

class PrometheusMetricsConfigParserPlugin : public ConfigParserPlugin {
 public:
  std::vector<std::string> keys() const override {
    return {configParserRootKey};
  }

  Status setUp() override;
  Status update(const std::string& source, const ParserConfig& config) override;
};
}
