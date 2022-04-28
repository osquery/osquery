/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/flags.h>
#include <osquery/database/database.h>
#include <osquery/logger/logger.h>
#include <osquery/registry/registry.h>
#include <osquery/sql/sqlite_util.h>

#include <sqlite3.h>

namespace osquery {

DECLARE_string(disable_tables);

std::set<std::string> kDisabledFuzzingTables = {
    "file",
    "hash",
    "yara",
};

int osqueryFuzzerInitialize(int* argc, char*** argv) {
  osquery::registryAndPluginInit();
  osquery::initDatabasePluginForTesting();

  std::string disabled_tables;
  for (auto table_name : kDisabledFuzzingTables) {
    disabled_tables += table_name;
    disabled_tables += ',';
  }

  if (!disabled_tables.empty()) {
    disabled_tables.pop_back();
  }

  // Set the tables to disable in the flags; we cannot use the detach operation
  FLAGS_disable_tables = disabled_tables;

  auto* db = osquery::SQLiteDBManager::instance().get()->db();

  // See https://www.sqlite.org/src/artifact/18af635f about limiting what
  // effects the fuzzer triggers.
  sqlite3_limit(db, SQLITE_LIMIT_VDBE_OP, 25000);
  sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 50000);

  FLAGS_minloglevel = 4;

  return 0;
}
} // namespace osquery
