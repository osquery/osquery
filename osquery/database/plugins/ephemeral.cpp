/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/database.h>
#include <osquery/logger.h>
#include <osquery/registry.h>

namespace osquery {

DECLARE_string(database_path);

class EphemeralDatabasePlugin : public DatabasePlugin {
  using DBType = std::map<std::string, std::map<std::string, std::string>>;

 public:
  /// Data retrieval method.
  Status get(const std::string& domain,
             const std::string& key,
             std::string& value) const override;

  /// Data storage method.
  Status put(const std::string& domain,
             const std::string& key,
             const std::string& value) override;

  /// Data removal method.
  Status remove(const std::string& domain, const std::string& k) override;

  Status removeRange(const std::string& domain,
                     const std::string& low,
                     const std::string& high) override;

  /// Key/index lookup method.
  Status scan(const std::string& domain,
              std::vector<std::string>& results,
              const std::string& prefix,
              size_t max) const override;

 public:
  /// Database workflow: open and setup.
  Status setUp() override {
    DBType().swap(db_);
    return Status(0);
  }

 private:
  DBType db_;
};

/// Backing-storage provider for osquery internal/core.
REGISTER_INTERNAL(EphemeralDatabasePlugin, "database", "ephemeral");

Status EphemeralDatabasePlugin::get(const std::string& domain,
                                    const std::string& key,
                                    std::string& value) const {
  if (db_.count(domain) > 0 && db_.at(domain).count(key) > 0) {
    value = db_.at(domain).at(key);
    return Status(0);
  } else {
    return Status(1);
  }
}

Status EphemeralDatabasePlugin::put(const std::string& domain,
                                    const std::string& key,
                                    const std::string& value) {
  db_[domain][key] = value;
  return Status(0);
}

Status EphemeralDatabasePlugin::remove(const std::string& domain,
                                       const std::string& k) {
  db_[domain].erase(k);
  return Status(0);
}

Status EphemeralDatabasePlugin::removeRange(const std::string& domain,
                                            const std::string& low,
                                            const std::string& high) {
  std::vector<std::string> keys;
  for (const auto& it : db_[domain]) {
    if (it.first >= low && it.first <= high) {
      keys.push_back(it.first);
    }
  }

  for (const auto& key : keys) {
    db_[domain].erase(key);
  }
  return Status(0);
}

Status EphemeralDatabasePlugin::scan(const std::string& domain,
                                     std::vector<std::string>& results,
                                     const std::string& prefix,
                                     size_t max) const {
  if (db_.count(domain) == 0) {
    return Status(0);
  }

  for (const auto& key : db_.at(domain)) {
    if (!prefix.empty() &&
        !(std::mismatch(prefix.begin(), prefix.end(), key.first.begin())
              .first == prefix.end())) {
      continue;
    }
    results.push_back(key.first);
    if (max > 0 && results.size() >= max) {
      break;
    }
  }
  return Status(0);
}
}
