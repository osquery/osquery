/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <set>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

namespace rj = rapidjson;

namespace osquery {

/**
 * @brief Flag names that effect the verbosity of status logs.
 *
 * If any of these options are present, then ask the logger to reconfigure
 * the verbosity.
 */
const std::set<std::string> kVerboseOptions{
    "verbose",
    "verbose_debug",
    "debug",
    "minloglevel",
    "logger_min_status",
    "stderrthreshold",
    "logger_min_stderr",
    "logger_stderr",
    "logtostderr",
    "alsologtostderr",
};

/**
 * @brief A simple ConfigParserPlugin for an "options" dictionary key.
 */
class OptionsConfigParserPlugin : public ConfigParserPlugin {
 public:
  std::vector<std::string> keys() const override {
    return {"options"};
  }

  Status update(const std::string& source, const ParserConfig& config) override;
};

Status OptionsConfigParserPlugin::update(const std::string& source,
                                         const ParserConfig& config) {
  auto co = config.find("options");
  if (co == config.end()) {
    return Status();
  }

  if (!data_.doc().HasMember("options")) {
    auto obj = data_.getObject();
    data_.add("options", obj);
  }

  if (co->second.doc().IsObject()) {
    auto obj = data_.getObject();
    data_.copyFrom(co->second.doc(), obj);
    data_.mergeObject(data_.doc()["options"], obj);
  }

  const auto& options = data_.doc()["options"];
  for (const auto& option : options.GetObject()) {
    std::string name = option.name.GetString();
    std::string value;
    if (option.value.IsString()) {
      value = option.value.GetString();
    } else if (option.value.IsBool()) {
      value = (option.value.GetBool()) ? "true" : "false";
    } else if (option.value.IsInt()) {
      value = std::to_string(option.value.GetInt());
    } else if (option.value.IsNumber()) {
      value = std::to_string(option.value.GetUint64());
    }

    if (value.empty() || name.empty()) {
      continue;
    }

    bool is_custom = name.find("custom_") == 0;
    if (!is_custom && Flag::getType(name).empty()) {
      LOG(WARNING) << "Cannot set unknown or invalid flag: " << name;
    }

    Flag::updateValue(name, value);
    // There is a special case for supported Gflags-reserved switches.
    if (kVerboseOptions.count(name)) {
      setVerboseLevel();
      if (Flag::getValue("verbose") == "true") {
        VLOG(1) << "Verbose logging enabled by config option";
      }
    }
  }

  return Status();
}

REGISTER_INTERNAL(OptionsConfigParserPlugin, "config_parser", "options");
}
