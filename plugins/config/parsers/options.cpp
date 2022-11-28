/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <set>

#include <osquery/config/config.h>
#include <osquery/core/flags.h>
#include <osquery/logger/data_logger.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/utils/json/json.h>

namespace osquery {

/**
 * @brief Flag names that effect the verbosity of status logs.
 *
 * If any of these options are present, then ask the logger to reconfigure
 * the verbosity.
 */
const std::set<std::string> kVerboseOptions{
    "verbose",
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

  {
    auto doc = JSON::newObject();

    {
      auto obj = doc.getObject();
      if (data_.doc().HasMember("options")) {
        doc.copyFrom(data_.doc()["options"], obj);
      }
      doc.add("options", obj);
    }

    if (co->second.doc().IsObject()) {
      auto obj = doc.getObject();
      doc.copyFrom(co->second.doc(), obj);
      doc.mergeObject(doc.doc()["options"], obj);
    }

    data_ = std::move(doc);
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
    } else if (option.value.IsObject() || option.value.IsArray()) {
      auto doc = JSON::newFromValue(option.value);
      doc.toString(value);
    } else {
      LOG(WARNING) << "Cannot parse unknown value type for option: " << name;
    }

    if (value.empty() || name.empty()) {
      continue;
    }

    bool is_custom = name.find("custom_") == 0;
    if (!is_custom && Flag::getType(name).empty()) {
      LOG(WARNING) << "Cannot set unknown or invalid flag: " << name;
      continue;
    }

    if (Flag::isCLIOnlyFlag(name)) {
      LOG(WARNING) << "The CLI only flag --" << name
                   << " set via config file will be ignored, please use a "
                      "flagfile or pass it to the process at startup";
      continue;
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
} // namespace osquery
