/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <set>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

namespace pt = boost::property_tree;

namespace osquery {

/**
 * @brief Flag names that effect the verbosity of status logs.
 *
 * If any of these options are present, then ask the logger to reconfigure
 * the verbosity.
 */
const std::set<std::string> kVerboseOptions{
    "verbose", "logger_min_status", "verbose_debug", "debug", "minloglevel",
};

/**
 * @brief A simple ConfigParserPlugin for an "options" dictionary key.
 */
class OptionsConfigParserPlugin : public ConfigParserPlugin {
 public:
  std::vector<std::string> keys() const override {
    return {"options"};
  }

  Status setUp() override;

  Status update(const std::string& source, const ParserConfig& config) override;
};

Status OptionsConfigParserPlugin::setUp() {
  data_.put_child("options", pt::ptree());
  return Status(0, "OK");
}

Status OptionsConfigParserPlugin::update(const std::string& source,
                                         const ParserConfig& config) {
  if (config.count("options") > 0) {
    data_ = pt::ptree();
    data_.put_child("options", config.at("options"));
  }

  const auto& options = data_.get_child("options");
  for (const auto& option : options) {
    std::string value = options.get<std::string>(option.first, "");
    if (value.empty()) {
      continue;
    }

    bool is_custom = option.first.find("custom_") == 0;
    if (!is_custom && Flag::getType(option.first).empty()) {
      LOG(WARNING) << "Cannot set unknown or invalid flag: " << option.first;
    }

    Flag::updateValue(option.first, value);
    // There is a special case for supported Gflags-reserved switches.
    if (kVerboseOptions.count(option.first)) {
      setVerboseLevel();
      if (Flag::getValue("verbose") == "true") {
        VLOG(1) << "Verbose logging enabled by config option";
      }
    }
  }

  return Status(0, "OK");
}

REGISTER_INTERNAL(OptionsConfigParserPlugin, "config_parser", "options");
}
