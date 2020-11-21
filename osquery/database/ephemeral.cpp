/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/database/database.h>
#include <osquery/registry/registry_factory.h>

#include <boost/variant.hpp>

#include <iostream>

namespace osquery {

class EphemeralDatabasePlugin : public DatabasePlugin {
  using DBType =
      std::map<std::string,
               std::map<std::string, boost::variant<int, std::string>>>;
  template <typename T>
  Status getAny(const std::string& domain,
                const std::string& key,
                T& value) const;

 private:
  void setValue(const std::string& domain,
                const std::string& key,
                const std::string& value);

  void setValue(const std::string& domain, const std::string& key, int value);

 public:
  /// Data retrieval method.

  Status get(const std::string& domain,
             const std::string& key,
             std::string& value) const override;
  Status get(const std::string& domain,
             const std::string& key,
             int& value) const override;
  /// Data storage method.
  Status put(const std::string& domain,
             const std::string& key,
             const std::string& value) override;
  Status put(const std::string& domain,
             const std::string& key,
             int value) override;

  Status putBatch(const std::string& domain,
                  const DatabaseStringValueList& data) override;

  /// Data removal method.
  Status remove(const std::string& domain, const std::string& k) override;

  Status removeRange(const std::string& domain,
                     const std::string& low,
                     const std::string& high) override;

  /// Key/index lookup method.
  Status scan(const std::string& domain,
              std::vector<std::string>& results,
              const std::string& prefix,
              uint64_t max) const override;

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

template <typename T>
Status EphemeralDatabasePlugin::getAny(const std::string& domain,
                                       const std::string& key,
                                       T& value) const {
  auto domainIterator = db_.find(domain);
  if (domainIterator == db_.end()) {
    return Status(1, "Domain " + domain + " does not exist");
  }

  auto keyIterator = domainIterator->second.find(key);
  if (keyIterator == domainIterator->second.end()) {
    return Status(1, "Key " + key + " in domain " + domain + " does not exist");
  }

  try {
    value = boost::get<T>(keyIterator->second);
  } catch (const boost::bad_get& e) {
    return Status(1,
                  "Type error getting string value for " + key + " in domain " +
                      domain + ": " + e.what());
  }
  return Status(0);
}

Status EphemeralDatabasePlugin::get(const std::string& domain,
                                    const std::string& key,
                                    std::string& value) const {
  return this->getAny(domain, key, value);
}
Status EphemeralDatabasePlugin::get(const std::string& domain,
                                    const std::string& key,
                                    int& value) const {
  return this->getAny(domain, key, value);
}

void EphemeralDatabasePlugin::setValue(const std::string& domain,
                                       const std::string& key,
                                       const std::string& value) {
  db_[domain][key] = value;
}

void EphemeralDatabasePlugin::setValue(const std::string& domain,
                                       const std::string& key,
                                       int value) {
  db_[domain][key] = value;
}

Status EphemeralDatabasePlugin::put(const std::string& domain,
                                    const std::string& key,
                                    const std::string& value) {
  setValue(domain, key, value);
  return Status(0);
}

Status EphemeralDatabasePlugin::put(const std::string& domain,
                                    const std::string& key,
                                    int value) {
  setValue(domain, key, value);
  return Status(0);
}

Status EphemeralDatabasePlugin::putBatch(const std::string& domain,
                                         const DatabaseStringValueList& data) {
  for (const auto& p : data) {
    const auto& key = p.first;
    const auto& value = p.second;

    setValue(domain, key, value);
  }

  return Status::success();
}

Status EphemeralDatabasePlugin::remove(const std::string& domain,
                                       const std::string& k) {
  db_[domain].erase(k);
  return Status(0);
}

Status EphemeralDatabasePlugin::removeRange(const std::string& domain,
                                            const std::string& low,
                                            const std::string& high) {
  if (low > high) {
    return Status::failure("Invalid range: low > high");
  }

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
                                     uint64_t max) const {
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
} // namespace osquery
