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
#include <osquery/registry.h>

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
    auto obj = data_.getObject();
    data_.copyFrom(events->second.doc(), obj);
    data_.add("events", obj, data_.doc());
  }
  return Status();
}

REGISTER_INTERNAL(EventsConfigParserPlugin, "config_parser", "events");
}
