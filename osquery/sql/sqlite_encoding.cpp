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

enum B64Type {
  B64_ENCODE_CONDITIONAL = 1,
  B64_ENCODE = 2,
  B64_DECODE = 4,
};

static void b64SqliteValue(sqlite3_context* ctx,
                           int argc,
                           sqlite3_value** argv,
                           unsigned int encode) {
  if (argc == 0) {
    return;
  }

  if (SQLITE_NULL == sqlite3_value_type(argv[0])) {
    sqlite3_result_null(ctx);
    return;
  }

  std::string input((char*)sqlite3_value_text(argv[0]));
  std::string result;
  if (encode & B64_ENCODE) {
    if ((encode & B64_ENCODE_CONDITIONAL) && !isPrintable(input)) {
      result = base64Encode(input);
    } else {
      result = input;
    }
  } else if (encode & B64_DECODE) {
    result = base64Decode(input);
  }
  sqlite3_result_text(
      ctx, result.c_str(), static_cast<int>(result.size()), SQLITE_TRANSIENT);
}

static void sqliteB64ConditionalEncFunc(sqlite3_context* context,
                                        int argc,
                                        sqlite3_value** argv) {
  b64SqliteValue(context, argc, argv, B64_ENCODE | B64_ENCODE_CONDITIONAL);
}

static void sqliteB64EncFunc(sqlite3_context* context,
                             int argc,
                             sqlite3_value** argv) {
  b64SqliteValue(context, argc, argv, B64_ENCODE);
}

static void sqliteB64DecFunc(sqlite3_context* context,
                             int argc,
                             sqlite3_value** argv) {
  b64SqliteValue(context, argc, argv, B64_DECODE);
}

void registerEncodingExtensions(sqlite3* db) {
  sqlite3_create_function(db,
                          "conditional_base64",
                          1,
                          SQLITE_UTF8,
                          nullptr,
                          sqliteB64ConditionalEncFunc,
                          nullptr,
                          nullptr);
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
