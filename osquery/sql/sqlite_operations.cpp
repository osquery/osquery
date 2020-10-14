/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <set>
#include <string>

#include <osquery/carver/carver_utils.h>
#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/mutex.h>

#include <sqlite3.h>

namespace osquery {

CLI_FLAG(bool,
         carver_disable_function,
         true,
         "Disable the osquery file carver function (default true)");

/// Global set of requested carve paths.
static std::set<std::string> kFunctionCarvePaths;

/// Mutex to protect access to carve paths.
Mutex kFunctionCarveMutex;

static void addCarveFile(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
  if (argc == 0) {
    return;
  }

  if (SQLITE_NULL == sqlite3_value_type(argv[0])) {
    sqlite3_result_null(ctx);
    return;
  }

  WriteLock lock(kFunctionCarveMutex);
  std::string path((const char*)sqlite3_value_text(argv[0]));
  kFunctionCarvePaths.insert(path);

  sqlite3_result_text(
      ctx, path.c_str(), static_cast<int>(path.size()), SQLITE_TRANSIENT);
}

static void executeCarve(sqlite3_context* ctx) {
  WriteLock lock(kFunctionCarveMutex);
  if (!FLAGS_carver_disable_function) {
    carvePaths(kFunctionCarvePaths);
    sqlite3_result_text(ctx, "Carve Started", 13, SQLITE_TRANSIENT);
  } else {
    LOG(WARNING) << "Carver as a function is disabled";
    sqlite3_result_text(ctx, "Carve Failed", 13, SQLITE_TRANSIENT);
  }
  kFunctionCarvePaths.clear();
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
} // namespace osquery
