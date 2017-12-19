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

namespace pt = boost::property_tree;

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
  data_.put_child("events", pt::ptree());
  return Status(0, "OK");
}

Status EventsConfigParserPlugin::update(const std::string& source,
                                        const ParserConfig& config) {
  if (config.count("events") > 0) {
    data_ = pt::ptree();
    data_.put_child("events", config.at("events"));
  }
  return Status(0, "OK");
}

REGISTER_INTERNAL(EventsConfigParserPlugin, "config_parser", "events");
}
