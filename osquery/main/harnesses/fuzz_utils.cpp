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

int osqueryFuzzerInitialize(int* argc, char*** argv) {
  osquery::registryAndPluginInit();
  osquery::initDatabasePluginForTesting();

  auto* db = osquery::SQLiteDBManager::instance().get()->db();

  // See https://www.sqlite.org/src/artifact/18af635f about limiting what
  // effects the fuzzer triggers.
  sqlite3_limit(db, SQLITE_LIMIT_VDBE_OP, 25000);
  sqlite3_limit(db, SQLITE_LIMIT_LENGTH, 50000);

  osquery::PluginRequest r;
  r["action"] = "detach";
  r["table"] = "file";

  osquery::PluginResponse rsp;
  osquery::Registry::get().call("sql", r, rsp);
  FLAGS_minloglevel = 4;

  return 0;
}
} // namespace osquery
