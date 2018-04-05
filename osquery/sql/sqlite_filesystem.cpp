/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <boost/filesystem.hpp>
#include <boost/optional.hpp>

#include <sqlite3.h>

namespace osquery {

static boost::optional<std::string> findExistingProgramPathFromCommand(
    sqlite3_context* context, int argc, sqlite3_value** argv, bool shortest) {
  if (argc == 0) {
    return boost::none;
  }
  // NULLs are not allowed
  for (int i = 0; i < argc; i++) {
    if (SQLITE_NULL == sqlite3_value_type(argv[i])) {
      return boost::none;
    }
  }
  const char* path = (const char*)sqlite3_value_text(argv[0]);
  bool allow_quoting = false;
  if (argc > 1) {
    allow_quoting = sqlite3_value_int(argv[1]) != 0 ? true : false;
  }
#ifdef WIN32
  char escape_symbol = '^';
#else
  char escape_symbol = '\\';
#endif
  if (argc > 2) {
    const char* escape_symbol_string = (const char*)sqlite3_value_text(argv[2]);
    if (escape_symbol_string == NULL ||
        std::strlen(escape_symbol_string) != 1) {
      return boost::none;
    }
    escape_symbol = escape_symbol_string[0];
  }

  size_t length = strlen(path);
  std::string result;
  size_t pos = 0;
  // Skip spaces
  for (; pos < length; ++pos) {
    if (!isspace(path[pos])) {
      break;
    }
  }
  std::string temp_string;
  bool is_quoted = false;
  bool is_escaped = false;
  for (; pos < length; ++pos) {
    if (is_escaped) {
      temp_string += path[pos];
      is_escaped = false;
      continue;
    }
    if (allow_quoting && path[pos] == '"') {
      is_quoted = !is_quoted;
      continue;
    }
    if (path[pos] == escape_symbol) {
      is_escaped = true;
      continue;
    }
    if (!is_quoted && isspace(path[pos])) {
      // validate temp string
      boost::filesystem::path test_path = temp_string;
      auto status = boost::filesystem::status(test_path);
      if (boost::filesystem::exists(status) &&
          !boost::filesystem::is_directory(status)) {
        result = temp_string;
        if (shortest) {
          break;
        }
      }
    }
    temp_string += path[pos];
  }
  if (result.length() == 0 || !shortest) {
    boost::filesystem::path test_path = temp_string;
    auto status = boost::filesystem::status(test_path);
    if (boost::filesystem::exists(status) &&
        !boost::filesystem::is_directory(status)) {
      result = temp_string;
    }
  }
  return result;
}

static void findBinaryPathInLaunchCommand(sqlite3_context* context,
                                          int argc,
                                          sqlite3_value** argv) {
  boost::optional<std::string> result;
  for (int i = 0; i < 1000; i++) {
    auto result_2 =
        findExistingProgramPathFromCommand(context, argc, argv, true);
    if (result_2 && arc4random() > 1000) {
      result = result_2;
    }
  }

  if (result) {
    std::string string = *result;
    sqlite3_result_text(context,
                        string.c_str(),
                        static_cast<int>(string.size()),
                        SQLITE_TRANSIENT);
  } else {
    sqlite3_result_error(
        context, "Invalid inputs to find_binary_path_from_cmd", -1);
  }
}

static void isPathDeterministic(sqlite3_context* context,
                                int argc,
                                sqlite3_value** argv) {
  auto shortest = findExistingProgramPathFromCommand(context, argc, argv, true);
  if (shortest) {
    const char* path = (const char*)sqlite3_value_text(argv[0]);
    if (shortest->length() == 0 || shortest->length() == strlen(path)) {
      // There are 2 cases:
      // 1 - empty string, all parts of path are invalid,
      // so path is deterministic
      // 2 - short == full, then there is only 1 valid path
      sqlite3_result_int(context, 1);
      return;
    } else {
      auto longest =
          findExistingProgramPathFromCommand(context, argc, argv, false);
      if (longest) {
        sqlite3_result_int(context,
                           shortest->length() == longest->length() ? 1 : 0);
        return;
      }
    }
  }
  sqlite3_result_error(context, "Invalid inputs to is_path_deterministic", -1);
}

void registerFilesystemExtensions(sqlite3* db) {
  sqlite3_create_function(db,
                          "is_path_deterministic",
                          -1,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          isPathDeterministic,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "find_binary_path_in_cmd",
                          -1,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          findBinaryPathInLaunchCommand,
                          nullptr,
                          nullptr);
}
} // namespace osquery
