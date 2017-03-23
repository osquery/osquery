/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <openssl/ecdsa.h>
#include <openssl/pem.h>

#include <osquery/config.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/core/signing.h"
#include "osquery/tables/system/hash.h"

#include "osquery/core/json.h"

namespace pt = boost::property_tree;

namespace osquery {

class StrictModeConfigParserPlugin : public ConfigParserPlugin {
 public:
  StrictModeConfigParserPlugin();
  virtual ~StrictModeConfigParserPlugin() {}

  std::vector<std::string> keys() const override {
    return {
        "strict_mode",
    };
  }

  Status setUp() override {
    setDatabaseValue(kPersistentSettings, "strict_mode_enabled", "false");
    return Status(0);
  };

  Status update(const std::string& source, const ParserConfig& config) override;

 private:
};

StrictModeConfigParserPlugin::StrictModeConfigParserPlugin() {
  data_.put_child("strict_mode", pt::ptree());
}

Status StrictModeConfigParserPlugin::update(const std::string& source,
                                            const ParserConfig& config) {
  if (config.count("strict_mode") > 0) {
    data_.put_child("strict_mode", config.at("strict_mode"));
  }

  if (data_.get_child("strict_mode").empty()) {
    return Status(0);
  }

  // Check that strict_mode is well formed
  auto strict_mode = data_.get_child("strict_mode");
  if (!(strict_mode.count("pub_key") == 1 &&
        strict_mode.count("protected_tables") == 1 &&
        strict_mode.count("protected_tables_sig") == 1 &&
        strict_mode.count("uuid_signing") == 1) &&
      strict_mode.count("counter_mode") == 1) {
    LOG(ERROR) << "Strict mode is not configured correctly";
    Initializer::requestShutdown(EXIT_CATASTROPHIC);
  } else {
    LOG(INFO) << "Verifying Strict Mode";
    // Pull out:
    // The public key
    // The signature for the protected tables
    // The UUID signing requirement
    // The list of protected tables
    std::string b64Pub = strict_mode.get_child("pub_key").get_value("");
    std::string b64Sig =
        strict_mode.get_child("protected_tables_sig").get_value("");
    std::string uuid_signing =
        strict_mode.get_child("uuid_signing").get_value("");
    std::string counter_mode =
        strict_mode.get_child("counter_mode").get_value("");

    std::string protected_tables;
    for (const auto& item : strict_mode.get_child("protected_tables")) {
      protected_tables.append(item.second.get_value("") + ",");
    }
    Status strict_status = verifySignature(b64Pub, b64Sig, protected_tables);
    // Strict mode tried to start but failed in verification, we should quit
    if (!strict_status.ok()) {
      LOG(ERROR) << strict_status.getMessage();
      Initializer::requestShutdown(EXIT_CATASTROPHIC);
    }

    // Pull out all the previous values and notify through logs if the values
    // have changed
    std::string old_key;
    std::string old_uuid_signing;
    std::string old_counter_mode;
    std::string old_protected_tables;
    std::string query_counter;
    getDatabaseValue(kPersistentSettings, "strict_mode_pub_key", old_key);
    getDatabaseValue(
        kPersistentSettings, "strict_mode_uuid_signing", old_uuid_signing);
    getDatabaseValue(
        kPersistentSettings, "strict_mode_tables", old_protected_tables);
    getDatabaseValue(
        kPersistentSettings, "strict_mode_query_counter", query_counter);
    getDatabaseValue(
        kPersistentSettings, "strict_mode_counter_mode", old_counter_mode);

    if (old_key != b64Pub) {
      LOG(WARNING) << "osquery had its strict mode key changed!";
      setDatabaseValue(kPersistentSettings, "strict_mode_pub_key", b64Pub);
    }
    if (old_uuid_signing != uuid_signing) {
      LOG(WARNING) << "osquery had uuid_signing requirement changed!";
      setDatabaseValue(
          kPersistentSettings, "strict_mode_uuid_signing", uuid_signing);
    }
    if (old_protected_tables != protected_tables) {
      LOG(WARNING) << "osquery had its protected tables changed!";
      setDatabaseValue(
          kPersistentSettings, "strict_mode_tables", protected_tables);
    }
    if (old_counter_mode != counter_mode) {
      LOG(WARNING) << "osquery had its counter mode changed!";
      setDatabaseValue(
          kPersistentSettings, "strict_mode_counter_mode", counter_mode);
    }
    if (query_counter == "") {
      LOG(WARNING) << "osquery could not find a query count, starting at 0";
      setDatabaseValue(kPersistentSettings, "strict_mode_query_counter", "0");
    }
    setDatabaseValue(kPersistentSettings, "strict_mode_enabled", "true");
    LOG(INFO) << "osquery strict mode enabled";
  }
  return Status(0, "OK");
}

REGISTER_INTERNAL(StrictModeConfigParserPlugin, "config_parser", "strict_mode");
}
