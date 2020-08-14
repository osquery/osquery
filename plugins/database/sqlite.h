/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <mutex>

#include <sqlite3.h>

#include <osquery/core/flags.h>
#include <osquery/database/database.h>
#include <osquery/filesystem/fileops.h>
#include <osquery/registry/registry_factory.h>

namespace osquery {

DECLARE_string(database_path);

class SQLiteDatabasePlugin : public DatabasePlugin {
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

  /// Data range removal method.
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
  Status setUp() override;

  /// Database workflow: close and cleanup.
  void tearDown() override {
    close();
  }

  /// Need to tear down open resources,
  virtual ~SQLiteDatabasePlugin() {
    close();
  }

 private:
  void close();

 private:
  /// The long-lived sqlite3 database.
  sqlite3* db_{nullptr};

  /// Deconstruction mutex.
  Mutex close_mutex_;
};

/// Backing-storage provider for osquery internal/core.
REGISTER_INTERNAL(SQLiteDatabasePlugin, "database", "sqlite");

} // namespace osquery
