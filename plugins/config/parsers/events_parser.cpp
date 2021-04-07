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

namespace osquery {

/**
 * @brief A simple ConfigParserPlugin for an "events" dictionary key.
 */
class EventsConfigParserPlugin : public ConfigParserPlugin {
 public:
  std::vector<std::string> keys() const override {
    return {"events"};
  }

  Status setUp() override;

  Status update(const std::string& source, const ParserConfig& config) override;
};

Status EventsConfigParserPlugin::setUp() {
  auto obj = data_.getObject();
  data_.add("events", obj);
  return Status();
}

Status EventsConfigParserPlugin::update(const std::string& source,
                                        const ParserConfig& config) {
  auto events = config.find("events");
  if (events != config.end()) {
    auto doc = JSON::newObject();
    auto obj = doc.getObject();
    doc.copyFrom(events->second.doc(), obj);
    doc.add("events", obj);
    data_ = std::move(doc);
  }
  return Status();
}

REGISTER_INTERNAL(EventsConfigParserPlugin, "config_parser", "events");
}
