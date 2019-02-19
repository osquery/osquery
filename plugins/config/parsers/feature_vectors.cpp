/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <plugins/config/parsers/feature_vectors.h>
#include <osquery/config/config.h>
#include <osquery/registry_factory.h>

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
