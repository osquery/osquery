/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <mutex>

#include <sqlite3.h>

#include <osquery/database.h>
#include <osquery/registry_factory.h>

#include "osquery/filesystem/fileops.h"

namespace osquery {

DECLARE_string(database_path);

class SQLiteDatabasePlugin : public DatabasePlugin {
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

  /// Data range removal method.
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

}
