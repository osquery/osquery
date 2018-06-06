/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <string>

#include <sqlite3.h>

#include "osquery/core/conversions.h"

namespace osquery {

enum class B64Type {
  B64_ENCODE_CONDITIONAL = 1,
  B64_ENCODE = 2,
  B64_DECODE = 3,
};

static void b64SqliteValue(sqlite3_context* ctx,
                           int argc,
                           sqlite3_value** argv,
                           B64Type encode) {
  if (argc == 0) {
    return;
  }

  if (SQLITE_NULL == sqlite3_value_type(argv[0])) {
    sqlite3_result_null(ctx);
    return;
  }
  std::string input((char*)sqlite3_value_text(argv[0]));
  std::string result;
  switch (encode) {
  case B64Type::B64_ENCODE_CONDITIONAL:
    if (isPrintable(input)) {
      result = input;
      break;
    }
  case B64Type::B64_ENCODE:
    result = base64Encode(input);
    break;
  case B64Type::B64_DECODE:
    result = base64Decode(input);
    break;
  }
  sqlite3_result_text(
      ctx, result.c_str(), static_cast<int>(result.size()), SQLITE_TRANSIENT);
}

static void sqliteB64ConditionalEncFunc(sqlite3_context* context,
                                        int argc,
                                        sqlite3_value** argv) {
  b64SqliteValue(context, argc, argv, B64Type::B64_ENCODE_CONDITIONAL);
}

static void sqliteB64EncFunc(sqlite3_context* context,
                             int argc,
                             sqlite3_value** argv) {
  b64SqliteValue(context, argc, argv, B64Type::B64_ENCODE);
}

static void sqliteB64DecFunc(sqlite3_context* context,
                             int argc,
                             sqlite3_value** argv) {
  b64SqliteValue(context, argc, argv, B64Type::B64_DECODE);
}

void registerEncodingExtensions(sqlite3* db) {
  sqlite3_create_function(db,
                          "conditional_to_base64",
                          1,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          sqliteB64ConditionalEncFunc,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "to_base64",
                          1,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          sqliteB64EncFunc,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "from_base64",
                          1,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          sqliteB64DecFunc,
                          nullptr,
                          nullptr);
}
} // namespace osquery
