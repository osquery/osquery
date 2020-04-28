/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <osquery/database.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/registry.h>
#include <osquery/sql/sqlite_util.h>

#include <sqlite3.h>

namespace osquery {

DECLARE_bool(disable_database);

int osqueryFuzzerInitialize(int* argc, char*** argv) {
  osquery::registryAndPluginInit();

  FLAGS_disable_database = true;
  osquery::DatabasePlugin::setAllowOpen(true);
  osquery::DatabasePlugin::initPlugin();

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
