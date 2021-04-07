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
#include <osquery/registry/registry_factory.h>
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
    auto doc = JSON::newObject();
    auto obj = doc.getObject();
    doc.copyFrom(topics->second.doc(), obj);
    doc.add(kKafkaTopicParserRootKey, obj);
    data_ = std::move(doc);
  }
  return Status();
}

REGISTER_INTERNAL(KafkaTopicsConfigParserPlugin,
                  "config_parser",
                  "kafka_topics");
} // namespace osquery
