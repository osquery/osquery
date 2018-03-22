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

#include <sys/stat.h>

#include <osquery/database.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>

#include "osquery/filesystem/fileops.h"

namespace osquery {

DECLARE_string(database_path);

const std::map<std::string, std::string> kDBSettings = {
    {"synchronous", "OFF"},
    {"count_changes", "OFF"},
    {"default_temp_store", "2"},
    {"auto_vacuum", "FULL"},
    {"journal_mode", "OFF"},
    {"cache_size", "1000"},
    {"page_count", "1000"},
};

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

Status SQLiteDatabasePlugin::setUp() {
  if (!DatabasePlugin::kDBAllowOpen) {
    LOG(WARNING) << RLOG(1629) << "Not allowed to set up database plugin";
  }

  // Consume the current settings.
  // A configuration update may change them, but that does not affect state.
  path_ = FLAGS_database_path;

  if (pathExists(path_).ok() && !isReadable(path_).ok()) {
    return Status(1, "Cannot read database path: " + path_);
  }

  if (!DatabasePlugin::kDBChecking) {
    VLOG(1) << "Opening database handle: " << path_;
  }

  // Tests may trash calls to setUp, make sure subsequent calls do not leak.
  close();

  // Open the SQLite backing storage at path_
  auto result = sqlite3_open_v2(
      path_.c_str(),
      &db_,
      (SQLITE_OPEN_FULLMUTEX | SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE),
      nullptr);

  if (result != SQLITE_OK || db_ == nullptr) {
    if (DatabasePlugin::kDBRequireWrite) {
      close();
      // A failed open in R/W mode is a runtime error.
      return Status(1, "Cannot open database: " + std::to_string(result));
    }

    if (!DatabasePlugin::kDBChecking) {
      VLOG(1) << "Opening database failed: Continuing with read-only support";
    }

    read_only_ = true;
  }

  if (!read_only_) {
    for (const auto& domain : kDomains) {
      std::string q = "create table if not exists " + domain +
                      " (key TEXT PRIMARY KEY, value TEXT);";
      result = sqlite3_exec(db_, q.c_str(), nullptr, nullptr, nullptr);
      if (result != SQLITE_OK) {
        close();
        return Status(1, "Cannot create domain: " + domain);
      }
    }

    std::string settings;
    for (const auto& setting : kDBSettings) {
      settings += "PRAGMA " + setting.first + "=" + setting.second + "; ";
    }
    sqlite3_exec(db_, settings.c_str(), nullptr, nullptr, nullptr);
  }

  // RocksDB may not create/append a directory with acceptable permissions.
  if (!read_only_ && platformChmod(path_, S_IRWXU) == false) {
    close();
    return Status(1, "Cannot set permissions on database path: " + path_);
  }
  return Status(0);
}

void SQLiteDatabasePlugin::close() {
  WriteLock lock(close_mutex_);
  if (db_ != nullptr) {
    sqlite3_close(db_);
    db_ = nullptr;
  }
}

static int getData(void* argument, int argc, char* argv[], char* column[]) {
  if (argument == nullptr) {
    return SQLITE_MISUSE;
  }

  QueryData* qData = (QueryData*)argument;
  Row r;
  for (int i = 0; i < argc; i++) {
    if (column[i] != nullptr) {
      r[column[i]] = (argv[i] != nullptr) ? argv[i] : "";
    }
  }
  (*qData).push_back(std::move(r));
  return 0;
}

Status SQLiteDatabasePlugin::get(const std::string& domain,
                                 const std::string& key,
                                 std::string& value) const {
  QueryData results;
  char* err = nullptr;
  std::string q{"select value from " + domain + " where key = '" + key + "';"};
  sqlite3_exec(db_, q.c_str(), getData, &results, &err);
  if (err != nullptr) {
    sqlite3_free(err);
  }

  // Only assign value if the query found a result.
  if (results.size() > 0) {
    value = std::move(results[0]["value"]);
    return Status(0);
  }
  return Status(1);
}

static void tryVacuum(sqlite3* db) {
  std::string q =
      "SELECT (sum(s1.pageno + 1 == s2.pageno) * 1.0 / count(*)) < 0.01 as v "
      " FROM "
      "(SELECT pageno FROM dbstat ORDER BY path) AS s1,"
      "(SELECT pageno FROM dbstat ORDER BY path) AS s2 WHERE "
      "s1.rowid + 1 = s2.rowid; ";

  QueryData results;
  sqlite3_exec(db, q.c_str(), getData, &results, nullptr);
  if (results.size() > 0 && results[0]["v"].back() == '1') {
    sqlite3_exec(db, "vacuum;", nullptr, nullptr, nullptr);
  }
}

Status SQLiteDatabasePlugin::put(const std::string& domain,
                                 const std::string& key,
                                 const std::string& value) {
  if (read_only_) {
    return Status(0, "Database in readonly mode");
  }

  sqlite3_stmt* stmt = nullptr;
  std::string q{"insert or replace into " + domain + " values (?1, ?2);"};
  sqlite3_prepare_v2(db_, q.c_str(), -1, &stmt, nullptr);

  sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, value.c_str(), -1, SQLITE_STATIC);
  auto rc = sqlite3_step(stmt);
  if (rc != SQLITE_DONE) {
    return Status(1);
  }

  sqlite3_finalize(stmt);
  if (rand() % 10 == 0) {
    tryVacuum(db_);
  }
  return Status(0);
}

Status SQLiteDatabasePlugin::remove(const std::string& domain,
                                    const std::string& key) {
  if (read_only_) {
    return Status(0, "Database in readonly mode");
  }

  sqlite3_stmt* stmt = nullptr;
  std::string q{"delete from " + domain + " where key IN (?1);"};
  sqlite3_prepare_v2(db_, q.c_str(), -1, &stmt, nullptr);

  sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
  auto rc = sqlite3_step(stmt);
  if (rc != SQLITE_DONE) {
    return Status(1);
  }

  sqlite3_finalize(stmt);
  if (rand() % 10 == 0) {
    tryVacuum(db_);
  }
  return Status(0);
}

Status SQLiteDatabasePlugin::removeRange(const std::string& domain,
                                         const std::string& low,
                                         const std::string& high) {
  if (read_only_) {
    return Status(0, "Database in readonly mode");
  }

  sqlite3_stmt* stmt = nullptr;
  std::string q{"delete from " + domain + " where key >= ?1 and key <= ?2;"};
  sqlite3_prepare_v2(db_, q.c_str(), -1, &stmt, nullptr);

  sqlite3_bind_text(stmt, 1, low.c_str(), -1, SQLITE_STATIC);
  sqlite3_bind_text(stmt, 2, high.c_str(), -1, SQLITE_STATIC);
  auto rc = sqlite3_step(stmt);
  if (rc != SQLITE_DONE) {
    return Status(1);
  }

  sqlite3_finalize(stmt);
  if (rand() % 10 == 0) {
    tryVacuum(db_);
  }
  return Status(0);
}

Status SQLiteDatabasePlugin::scan(const std::string& domain,
                                  std::vector<std::string>& results,
                                  const std::string& prefix,
                                  size_t max) const {
  QueryData _results;
  char* err = nullptr;

  std::string q =
      "select key from " + domain + " where key LIKE '" + prefix + "%'";
  if (max > 0) {
    q += " limit " + std::to_string(max);
  }
  sqlite3_exec(db_, q.c_str(), getData, &_results, &err);
  if (err != nullptr) {
    sqlite3_free(err);
  }

  // Only assign value if the query found a result.
  for (auto& r : _results) {
    results.push_back(std::move(r["key"]));
  }

  return Status(0, "OK");
}
}
