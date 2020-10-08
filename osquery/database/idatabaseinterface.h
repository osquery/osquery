
/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#pragma once

#include <memory>
#include <string>
#include <vector>

#include <osquery/utils/status/status.h>

namespace osquery {
using DatabaseStringValueList =
    std::vector<std::pair<std::string, std::string>>;

class IDatabaseInterface {
 public:
  IDatabaseInterface() = default;
  virtual ~IDatabaseInterface() = default;

  virtual Status getDatabaseValue(const std::string& domain,
                                  const std::string& key,
                                  std::string& value) const = 0;

  virtual Status getDatabaseValue(const std::string& domain,
                                  const std::string& key,
                                  int& value) const = 0;

  virtual Status setDatabaseValue(const std::string& domain,
                                  const std::string& key,
                                  const std::string& value) const = 0;

  virtual Status setDatabaseValue(const std::string& domain,
                                  const std::string& key,
                                  int value) const = 0;

  virtual Status setDatabaseBatch(
      const std::string& domain, const DatabaseStringValueList& data) const = 0;

  virtual Status deleteDatabaseValue(const std::string& domain,
                                     const std::string& key) const = 0;

  virtual Status deleteDatabaseRange(const std::string& domain,
                                     const std::string& low,
                                     const std::string& high) const = 0;

  virtual Status scanDatabaseKeys(const std::string& domain,
                                  std::vector<std::string>& keys,
                                  size_t max) const = 0;

  virtual Status scanDatabaseKeys(const std::string& domain,
                                  std::vector<std::string>& keys,
                                  const std::string& prefix,
                                  size_t max) const = 0;

  IDatabaseInterface(const IDatabaseInterface&) = delete;
  IDatabaseInterface& operator=(const IDatabaseInterface&) = delete;
};
} // namespace osquery
