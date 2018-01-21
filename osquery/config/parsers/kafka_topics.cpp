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

#include "osquery/config/parsers/kafka_topics.h"

namespace osquery {

/// Root key to retrieve Kafka topic configurations.
const std::string kKafkaTopicParserRootKey("kafka_topics");

std::vector<std::string> KafkaTopicsConfigParserPlugin::keys() const {
  return {kKafkaTopicParserRootKey};
}

Status KafkaTopicsConfigParserPlugin::update(const std::string& source,
                                             const ParserConfig& config) {
  auto topics = config.find(kKafkaTopicParserRootKey);
  if (topics != config.end()) {
    auto obj = data_.getObject();
    data_.copyFrom(topics->second.doc(), obj);
    data_.add(kKafkaTopicParserRootKey, obj);
  }
  return Status();
}

REGISTER_INTERNAL(KafkaTopicsConfigParserPlugin,
                  "config_parser",
                  "kafka_topics");
} // namespace osquery
