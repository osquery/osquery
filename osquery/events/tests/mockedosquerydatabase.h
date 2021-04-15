/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/database/database.h>

#include <map>

namespace osquery {

class MockedOsqueryDatabase final : public IDatabaseInterface {
 public:
  mutable std::map<std::string, std::string> key_map;

  MockedOsqueryDatabase() = default;
  virtual ~MockedOsqueryDatabase() override = default;

  void generateEvents(const std::string& publisher, const std::string& name);

  virtual Status getDatabaseValue(const std::string& domain,
                                  const std::string& key,
                                  std::string& value) const override;

  virtual Status getDatabaseValue(const std::string& domain,
                                  const std::string& key,
                                  int& value) const override;

  virtual Status setDatabaseValue(const std::string& domain,
                                  const std::string& key,
                                  const std::string& value) const override;

  virtual Status setDatabaseValue(const std::string& domain,
                                  const std::string& key,
                                  int value) const override;

  virtual Status setDatabaseBatch(
      const std::string& domain,
      const DatabaseStringValueList& data) const override;

  virtual Status deleteDatabaseValue(const std::string& domain,
                                     const std::string& key) const override;

  virtual Status deleteDatabaseRange(const std::string& domain,
                                     const std::string& low,
                                     const std::string& high) const override;

  virtual Status scanDatabaseKeys(const std::string& domain,
                                  std::vector<std::string>& keys,
                                  size_t max) const override;

  virtual Status scanDatabaseKeys(const std::string& domain,
                                  std::vector<std::string>& keys,
                                  const std::string& prefix,
                                  size_t max) const override;
};

} // namespace osquery
