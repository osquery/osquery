/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <set>
#include <string>

#include <osquery/carver/carver.h>
#include <osquery/flags.h>
#include <osquery/logger.h>
#include <osquery/utils/conversions/split.h>
#include <osquery/utils/mutex.h>

#include <sqlite3.h>

namespace osquery {

/// Global set of requested carve paths.
static std::set<std::string> kFunctionCarvePaths;

/// Mutex to protect access to carve paths.
Mutex kFunctionCarveMutex;

DECLARE_bool(carver_disable_function);

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
  } else {
    LOG(WARNING) << "Carver as a function is disabled";
  }
  kFunctionCarvePaths.clear();
  sqlite3_result_text(ctx, "Carve Started", 13, SQLITE_TRANSIENT);
}

static void setFlag(sqlite3_context* ctx, int argc, sqlite3_value** argv) {
  if (argc == 0) {
    return;
  }

  if (SQLITE_NULL == sqlite3_value_type(argv[0])) {
    sqlite3_result_null(ctx);
    return;
  }

  std::string f((const char*)sqlite3_value_text(argv[0]));
  auto i = f.find('=');
  if (i != std::string::npos) {
    std::string name = f.substr(0, i);
    std::string value = f.substr(i + 1);

    if (name.length() && value.length()) {
      std::string res =
          gflags::SetCommandLineOption(name.c_str(), value.c_str());

      if (res.length() && isspace(res[res.length() - 1])) {
        res.resize(res.length() - 1);
      }
      sqlite3_result_text(ctx, res.c_str(), res.length(), SQLITE_TRANSIENT);
    }
  }
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
  sqlite3_create_function(
      db, "flag", 1, SQLITE_UTF8, nullptr, setFlag, nullptr, nullptr);
}
} // namespace osquery
