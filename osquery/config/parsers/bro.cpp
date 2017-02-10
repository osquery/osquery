/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <osquery/status.h>
#include <osquery/system.h>

#include <osquery/config.h>
#include <osquery/flags.h>
#include <osquery/logger.h>

namespace pt = boost::property_tree;

namespace osquery {

/**
 * @brief A simple ConfigParserPlugin for a "bro" dictionary key.
 */
    class BroConfigParserPlugin : public ConfigParserPlugin {
    public:
        std::vector<std::string> keys() const override { return {"bro"}; }

        Status setUp() override;

        Status update(const std::string& source, const ParserConfig& config) override;
    };

    Status BroConfigParserPlugin::setUp() {
        data_.put_child("bro", pt::ptree());
        return Status(0, "OK");
    }

    Status BroConfigParserPlugin::update(const std::string& source,
                                             const ParserConfig& config) {
        if (config.count("bro") > 0) {
            data_ = pt::ptree();
            data_.put_child("bro", config.at("bro"));
        }

        const auto& options = data_.get_child("bro");
        for (const auto& option : options) {
            std::string value = options.get<std::string>(option.first, "");
            if (value.empty()) {
                continue;
            }

            if (Flag::getType(option.first).empty()) {
                LOG(WARNING) << "Cannot set unknown or invalid flag: " << option.first;
                return Status(1, "Unknown flag");
            }

            Flag::updateValue(option.first, value);
            // There is a special case for supported Gflags-reserved switches.
            if (option.first == "verbose" || option.first == "verbose_debug" ||
                option.first == "debug") {
                setVerboseLevel();
                if (Flag::getValue("verbose") == "true") {
                    VLOG(1) << "Verbose logging enabled by config option";
                }
            }
        }

        return Status(0, "OK");
    }

    REGISTER_INTERNAL(BroConfigParserPlugin, "config_parser", "bro");
}
