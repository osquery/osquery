/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <iostream>

#include <osquery/config/config.h>
#include <osquery/registry_factory.h>
#include <plugins/config/parsers/kafka_topics.h>

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
