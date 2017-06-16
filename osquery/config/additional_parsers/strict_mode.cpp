/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <openssl/ecdsa.h>
#include <openssl/pem.h>

#include <osquery/config.h>
#include <osquery/logger.h>

#include "osquery/core/signing.h"

#include "osquery/core/conversions.h"
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
    setDatabaseValue(kPersistentSettings, kStrictMode + ".enabled", "0");
    return Status(0);
  };

  Status update(const std::string& source, const ParserConfig& config) override;
};

StrictModeConfigParserPlugin::StrictModeConfigParserPlugin() {
  data_.put_child(kStrictMode, pt::ptree());
}

Status StrictModeConfigParserPlugin::update(const std::string& source,
                                            const ParserConfig& config) {
  if (config.count(kStrictMode) > 0) {
    data_.put_child(kStrictMode, config.at(kStrictMode));
  }

  if (data_.get_child(kStrictMode).empty()) {
    return Status(0);
  }

  // Check that strict_mode is well formed
  auto strict_mode = data_.get_child(kStrictMode);
  if (!(strict_mode.count(kStrictModePublicKey) == 1 &&
        strict_mode.count(kStrictModeProtectedTables) == 1 &&
        strict_mode.count(kStrictModeProtectedTablesSignature) == 1 &&
        strict_mode.count(kStrictModeUUIDSigning) == 1) &&
      strict_mode.count(kStrictModeCounterMode) == 1) {
    LOG(ERROR) << "Strict mode is not configured correctly";
    Initializer::requestShutdown(EXIT_CATASTROPHIC);
  } else {
    LOG(INFO) << "Verifying Strict Mode";
    std::string b64Pub = strict_mode.get<std::string>(kStrictModePublicKey, "");
    std::string b64Sig =
        strict_mode.get<std::string>(kStrictModeProtectedTablesSignature, "");
    std::string uuid_signing =
        strict_mode.get<std::string>(kStrictModeUUIDSigning, "");
    std::string counter_mode =
        strict_mode.get<std::string>(kStrictModeCounterMode, "");

    std::vector<std::string> protected_tables_vector;
    for (const auto& item : strict_mode.get_child(kStrictModeProtectedTables)) {
      protected_tables_vector.push_back(item.second.get_value(""));
    }
    std::string protected_tables = osquery::join(protected_tables_vector, ",");

    Status strict_status = verifySignature(b64Pub, b64Sig, protected_tables);
    // Strict mode tried to start but failed in verification, we should quit
    if (!strict_status.ok()) {
      LOG(ERROR) << "Cannot enable strict mode: " << strict_status.getMessage();
      Initializer::requestShutdown(EXIT_CATASTROPHIC);
    }

    // Pull out all the previous values and notify through logs if the values
    // have changed
    std::string old_key;
    std::string old_uuid_signing;
    std::string old_counter_mode;
    std::string old_protected_tables;
    std::string query_counter;
    getDatabaseValue(
        kPersistentSettings, kStrictMode + "." + kStrictModePublicKey, old_key);
    getDatabaseValue(kPersistentSettings,
                     kStrictMode + "." + kStrictModeUUIDSigning,
                     old_uuid_signing);
    getDatabaseValue(kPersistentSettings,
                     kStrictMode + "." + kStrictModeProtectedTables,
                     old_protected_tables);
    getDatabaseValue(kPersistentSettings,
                     kStrictMode + "." + kStrictModeUUIDSigning,
                     query_counter);
    getDatabaseValue(kPersistentSettings,
                     kStrictMode + "." + kStrictModeCounterMode,
                     old_counter_mode);

    if (old_key != b64Pub) {
      LOG(WARNING) << "Strict mode key changed";
      setDatabaseValue(kPersistentSettings,
                       kStrictMode + "." + kStrictModePublicKey,
                       b64Pub);
    }
    if (old_uuid_signing != uuid_signing) {
      LOG(WARNING) << "Strict mode uuid_signing requirement changed";
      setDatabaseValue(kPersistentSettings,
                       kStrictMode + "." + kStrictModeUUIDSigning,
                       uuid_signing);
    }
    if (old_protected_tables != protected_tables) {
      LOG(WARNING) << "Strict mode protected tables changed";
      setDatabaseValue(kPersistentSettings,
                       kStrictMode + "." + kStrictModeProtectedTables,
                       protected_tables);
    }
    if (old_counter_mode != counter_mode) {
      LOG(WARNING) << "Strict mode counter requirement changed";
      setDatabaseValue(kPersistentSettings,
                       kStrictMode + "." + kStrictModeCounterMode,
                       counter_mode);
    }
    if (query_counter == "") {
      LOG(WARNING) << "Strict mode no query count, reset to 0";
      setDatabaseValue(
          kPersistentSettings, kStrictMode + ".query_counter", "0");
    }
    setDatabaseValue(kPersistentSettings, kStrictMode + ".enabled", "1");
    LOG(INFO) << "Strict mode enabled";
  }
  return Status(0, "OK");
}

REGISTER_INTERNAL(StrictModeConfigParserPlugin, "config_parser", "strict_mode");
}
