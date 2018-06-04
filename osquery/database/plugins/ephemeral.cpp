/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <iostream>

#include "osquery/database/plugins/ephemeral.h"

namespace osquery {

Status EphemeralDatabasePlugin::get(const std::string& domain,
                                    const std::string& key,
                                    std::string& value) const {
  if (db_.count(domain) > 0 && db_.at(domain).count(key) > 0) {
    try {
      value = boost::get<std::string>(db_.at(domain).at(key));
    } catch (const std::exception& e) {
      LOG(WARNING) << "Type error getting string value for (domain,key) : ("
                   << key << "," << domain << ") " << e.what();
      return Status(
          1,
          "EphemeralDatabasePlugin::get was requested incorrect type(string)");
    }
    return Status(0);
  } else {
    return Status(1, "Key or domain does not exist");
  }
}

Status EphemeralDatabasePlugin::get(const std::string& domain,
                                    const std::string& key,
                                    int& value) const {
  if (db_.count(domain) > 0 && db_.at(domain).count(key) > 0) {
    try {
      value = boost::get<int>(db_.at(domain).at(key));
    } catch (const std::exception& e) {
      LOG(WARNING) << "Type error getting int value for (domain,key) : (" << key
                   << "," << domain << ") " << e.what();
      return Status(
          1, "EphemeralDatabasePlugin::get was requested incorrect type(int)");
    }
    return Status(0);
  } else {
    return Status(1, "Key or domain does not exist");
  }
}

Status EphemeralDatabasePlugin::put(const std::string& domain,
                                    const std::string& key,
                                    const std::string& value) {
  db_[domain][key] = value;
  return Status(0);
}

Status EphemeralDatabasePlugin::put(const std::string& domain,
                                    const std::string& key,
                                    const int& value) {
  db_[domain][key] = value;
  return Status(0);
}

void EphemeralDatabasePlugin::dumpDatabase() const {
  for (const auto& domainValue : db_) {
    const auto& domain = domainValue.first;
    for (const auto& keyValue : domainValue.second) {
      const auto& key = keyValue.first;
      const auto& value = keyValue.second;
      std::cout << domain << "[" << key << "]: " << value << std::endl;
    }
  }
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
