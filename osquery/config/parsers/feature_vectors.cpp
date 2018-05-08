/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/config.h>

#include "osquery/config/parsers/feature_vectors.h"

namespace osquery {

const std::string kFeatureVectorsRootKey{"feature_vectors"};

std::vector<std::string> FeatureVectorsConfigParserPlugin::keys() const {
  return {kFeatureVectorsRootKey};
}

Status FeatureVectorsConfigParserPlugin::update(const std::string& source,
                                                const ParserConfig& config) {
  auto fv = config.find(kFeatureVectorsRootKey);
  if (fv == config.end()) {
    return Status();
  }

  auto obj = data_.getObject();
  data_.copyFrom(fv->second.doc(), obj);
  data_.add(kFeatureVectorsRootKey, obj);
  return Status();
}

REGISTER_INTERNAL(FeatureVectorsConfigParserPlugin,
                  "config_parser",
                  "feature_vectors");
} // namespace osquery
