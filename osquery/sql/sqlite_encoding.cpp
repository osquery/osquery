/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <string>

#include <sqlite3.h>

#include "osquery/core/conversions.h"

namespace osquery {

static void b64SqliteValue(sqlite3_context* ctx,
                           int argc,
                           sqlite3_value** argv,
                           bool encode) {
  if (argc == 0) {
    return;
  }

  if (SQLITE_NULL == sqlite3_value_type(argv[0])) {
    sqlite3_result_null(ctx);
    return;
  }

  std::string input((char*)sqlite3_value_text(argv[0]));
  std::string result;
  if (encode) {
    result = base64Encode(input);
  } else {
    result = base64Decode(input);
  }
  sqlite3_result_text(
      ctx, result.c_str(), static_cast<int>(result.size()), SQLITE_TRANSIENT);
}

static void sqliteB64EncFunc(sqlite3_context* context,
                             int argc,
                             sqlite3_value** argv) {
  b64SqliteValue(context, argc, argv, true);
}

static void sqliteB64DecFunc(sqlite3_context* context,
                             int argc,
                             sqlite3_value** argv) {
  b64SqliteValue(context, argc, argv, false);
}

void registerEncodingExtensions(sqlite3* db) {
  sqlite3_create_function(db,
                          "base64",
                          1,
                          SQLITE_UTF8,
                          nullptr,
                          sqliteB64EncFunc,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "unbase64",
                          1,
                          SQLITE_UTF8,
                          nullptr,
                          sqliteB64DecFunc,
                          nullptr,
                          nullptr);
}
}
