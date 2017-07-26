/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#pragma once

#include <string>
#include <vector>

#include <osquery/config.h>

namespace osquery {

const std::string kKafkaTopicParserRootKey("kafka_topics");

class KafkaTopicsConfigParserPlugin : public ConfigParserPlugin {
 public:
  std::vector<std::string> keys() const override;
  Status setUp() override;
  Status update(const std::string& source, const ParserConfig& config) override;
};
} // namespace osquery
