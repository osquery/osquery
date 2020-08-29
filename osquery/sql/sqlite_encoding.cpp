/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <string>

#include <sqlite3.h>

#include <osquery/utils/base64.h>
#include <osquery/utils/chars.h>

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

  const auto* value = sqlite3_value_text(argv[0]);
  auto size = static_cast<size_t>(sqlite3_value_bytes(argv[0]));

  std::string input(reinterpret_cast<const char*>(value), size);
  std::string result;
  switch (encode) {
  case B64Type::B64_ENCODE_CONDITIONAL:
    if (isPrintable(input)) {
      result = input;
      break;
    }
  case B64Type::B64_ENCODE:
    result = base64::encode(input);
    break;
  case B64Type::B64_DECODE:
    result = base64::decode(input);
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
