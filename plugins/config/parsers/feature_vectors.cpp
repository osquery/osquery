/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/config/config.h>
#include <osquery/registry/registry_factory.h>
#include <plugins/config/parsers/feature_vectors.h>

namespace osquery {

const std::string kFeatureVectorsRootKey{"feature_vectors"};

std::vector<std::string> FeatureVectorsConfigParserPlugin::keys() const {
  return {kFeatureVectorsRootKey};
}

Status FeatureVectorsConfigParserPlugin::update(const std::string& source,
                                                const ParserConfig& config) {
  auto fv = config.find(kFeatureVectorsRootKey);
  if (fv == config.end()) {
    // No feature_vectors key.
    return Status::success();
  }

  if (!fv->second.doc().IsObject()) {
    // Expect feature_vectors to be an object.
    return Status::success();
  }

  auto doc = JSON::newObject();
  auto obj = doc.getObject();
  doc.copyFrom(fv->second.doc(), obj);
  doc.add(kFeatureVectorsRootKey, obj);
  data_ = std::move(doc);
  return Status::success();
}

REGISTER_INTERNAL(FeatureVectorsConfigParserPlugin,
                  "config_parser",
                  "feature_vectors");
} // namespace osquery
