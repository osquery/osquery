/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <set>
#include <string>

#include <osquery/flags.h>
#include <osquery/logger.h>

#include "osquery/carver/carver.h"
#include "osquery/core/conversions.h"

#include <sqlite3.h>

namespace osquery {

std::set<std::string> paths = {};

DECLARE_bool(carver_disable_function);

static void addCarveFile(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
  if (argc == 0) {
    return;
  }

  if (SQLITE_NULL == sqlite3_value_type(argv[0])) {
    sqlite3_result_null(ctx);
    return;
  }

  std::string path((char*)sqlite3_value_text(argv[0]));
  paths.insert(path);

  sqlite3_result_text(
      ctx, path.c_str(), static_cast<int>(path.size()), SQLITE_TRANSIENT);
}

static void executeCarve(sqlite3_context* ctx) {
  if (!FLAGS_carver_disable_function) {
    carvePaths(paths);
  } else {
    LOG(WARNING) << "Carver as a function disabled; nothing carved";
  }
  paths.clear();
  sqlite3_result_text(ctx, "Carve Started", 13, SQLITE_TRANSIENT);
}

void registerOperationExtensions(sqlite3* db) {
  sqlite3_create_function(db,
                          "carve",
                          1,
                          SQLITE_UTF8,
                          nullptr,
                          nullptr,
                          addCarveFile,
                          executeCarve);
}
}
