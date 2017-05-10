/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <functional>
#include <string>

#include "osquery/core/conversions.h"
#include "osquery/tables/system/hash.h"

#include <sqlite3.h>

namespace osquery {

static void hashSqliteValue(sqlite3_context* ctx,
                            int argc,
                            sqlite3_value** argv,
                            HashType ht) {
  if (argc == 0) {
    return;
  }

  if (SQLITE_NULL == sqlite3_value_type(argv[0])) {
    sqlite3_result_null(ctx);
    return;
  }

  // Parse and verify the split input parameters.
  std::string input((char*)sqlite3_value_text(argv[0]));

  auto result = hashFromBuffer(ht, input.data(), input.size());
  sqlite3_result_text(
      ctx, result.c_str(), static_cast<int>(result.size()), SQLITE_TRANSIENT);
}

static void sqliteMD5Func(sqlite3_context* context,
                          int argc,
                          sqlite3_value** argv) {
  hashSqliteValue(context, argc, argv, HASH_TYPE_MD5);
}

static void sqliteSHA1Func(sqlite3_context* context,
                           int argc,
                           sqlite3_value** argv) {
  hashSqliteValue(context, argc, argv, HASH_TYPE_SHA1);
}

static void sqliteSHA256Func(sqlite3_context* context,
                             int argc,
                             sqlite3_value** argv) {
  hashSqliteValue(context, argc, argv, HASH_TYPE_SHA256);
}

void registerHashingExtensions(sqlite3* db) {
  sqlite3_create_function(
      db, "md5", 1, SQLITE_UTF8, nullptr, sqliteMD5Func, nullptr, nullptr);
  sqlite3_create_function(
      db, "sha1", 1, SQLITE_UTF8, nullptr, sqliteSHA1Func, nullptr, nullptr);
  sqlite3_create_function(db,
                          "sha256",
                          1,
                          SQLITE_UTF8,
                          nullptr,
                          sqliteSHA256Func,
                          nullptr,
                          nullptr);
}
}
