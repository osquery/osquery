/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */
#pragma once

#include <string>
#include <vector>

#include <osquery/config/config.h>

namespace osquery {

extern const std::string kPrometheusParserRootKey;

class PrometheusMetricsConfigParserPlugin : public ConfigParserPlugin {
 public:
  std::vector<std::string> keys() const override;
  Status update(const std::string& source, const ParserConfig& config) override;
};
}
