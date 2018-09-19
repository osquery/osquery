/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#include <assert.h>

#ifdef WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <functional>
#include <string>
#include <vector>

#include <boost/algorithm/string/regex.hpp>
#include <boost/regex.hpp>

#include <osquery/utils/conversions/split.h>

#include <sqlite3.h>

namespace osquery {

using SplitResult = std::vector<std::string>;
using StringSplitFunction = std::function<SplitResult(
    const std::string& input, const std::string& tokens)>;

/**
 * @brief A simple SQLite column string split implementation.
 *
 * Split a column value using a single token and select an expected index.
 * If multiple characters are given to the token parameter, each is used to
 * split, similar to boost::is_any_of.
 *
 * Example:
 *   1. SELECT ip_address from addresses;
 *      192.168.0.1
 *   2. SELECT SPLIT(ip_address, ".", 1) from addresses;
 *      168
 *   3. SELECT SPLIT(ip_address, ".0", 0) from addresses;
 *      192
 */
static SplitResult tokenSplit(const std::string& input,
                              const std::string& tokens) {
  return osquery::split(input, tokens);
}

/**
 * @brief A regex SQLite column string split implementation.
 *
 * Split a column value using a single or multi-character token and select an
 * expected index. The token input is considered a regex.
 *
 * Example:
 *   1. SELECT ip_address from addresses;
 *      192.168.0.1
 *   2. SELECT SPLIT(ip_address, "\.", 1) from addresses;
 *      168
 *   3. SELECT SPLIT(ip_address, "\.0", 0) from addresses;
 *      192.168
 */
static SplitResult regexSplit(const std::string& input,
                              const std::string& token) {
  // Split using the token as a regex to support multi-character tokens.
  std::vector<std::string> result;
  boost::algorithm::split_regex(result, input, boost::regex(token));
  return result;
}

static void callStringSplitFunc(sqlite3_context* context,
                                int argc,
                                sqlite3_value** argv,
                                StringSplitFunction f) {
  assert(argc == 3);
  if (SQLITE_NULL == sqlite3_value_type(argv[0]) ||
      SQLITE_NULL == sqlite3_value_type(argv[1]) ||
      SQLITE_NULL == sqlite3_value_type(argv[2])) {
    sqlite3_result_null(context);
    return;
  }

  // Parse and verify the split input parameters.
  std::string input((char*)sqlite3_value_text(argv[0]));
  std::string token((char*)sqlite3_value_text(argv[1]));
  auto index = static_cast<size_t>(sqlite3_value_int(argv[2]));
  if (token.empty()) {
    // Allow the input string to be empty.
    sqlite3_result_error(context, "Invalid input to split function", -1);
    return;
  }

  auto result = f(input, token);
  if (index >= result.size()) {
    // Could emit a warning about a selected index that is out of bounds.
    sqlite3_result_null(context);
    return;
  }

  // Yield the selected index.
  const auto& selected = result[index];
  sqlite3_result_text(context,
                      selected.c_str(),
                      static_cast<int>(selected.size()),
                      SQLITE_TRANSIENT);
}

static void tokenStringSplitFunc(sqlite3_context* context,
                                 int argc,
                                 sqlite3_value** argv) {
  callStringSplitFunc(context, argc, argv, tokenSplit);
}

static void regexStringSplitFunc(sqlite3_context* context,
                                 int argc,
                                 sqlite3_value** argv) {
  callStringSplitFunc(context, argc, argv, regexSplit);
}

/**
 * @brief Convert an IPv4 string address to decimal.
 */
static void ip4StringToDecimalFunc(sqlite3_context* context,
                                   int argc,
                                   sqlite3_value** argv) {
  assert(argc == 1);

  if (SQLITE_NULL == sqlite3_value_type(argv[0])) {
    sqlite3_result_null(context);
    return;
  }

  struct sockaddr sa;
  std::string address((char*)sqlite3_value_text(argv[0]));
  if (address.find(':') != std::string::npos) {
    // Assume this is an IPv6 address.
    sqlite3_result_null(context);
  } else {
    auto in4 = (struct sockaddr_in*)&sa;
    if (inet_pton(AF_INET, address.c_str(), &(in4->sin_addr)) == 1) {
      sqlite3_result_int64(context, ntohl(in4->sin_addr.s_addr));
    } else {
      sqlite3_result_null(context);
    }
  }
}

/**
 * @brief Compare two software version strings
 */
static void versionLessFunc(sqlite3_context* context,
                            int argc,
                            sqlite3_value** argv) {
  assert(argc == 2);

  if (SQLITE_NULL == sqlite3_value_type(argv[0]) ||
      SQLITE_NULL == sqlite3_value_type(argv[1])) {
    sqlite3_result_null(context);
    return;
  }

  int major1 = 0, minor1 = 0, patch1 = 0, build1 = 0;
  std::sscanf((char*)sqlite3_value_text(argv[0]),
              "%d.%d.%d%*[.-]%d",
              &major1,
              &minor1,
              &patch1,
              &build1);
  int major2 = 0, minor2 = 0, patch2 = 0, build2 = 0;
  std::sscanf((char*)sqlite3_value_text(argv[1]),
              "%d.%d.%d%*[.-]%d",
              &major2,
              &minor2,
              &patch2,
              &build2);

  int result = false;
  if (major1 < major2) {
    result = true;
  } else if (major1 == major2) {
    if (minor1 < minor2) {
      result = true;
    } else if (minor1 == minor2) {
      if (patch1 < patch2) {
        result = true;
      } else if (patch1 == patch2) {
        result = build1 < build2;
      }
    }
  }

  sqlite3_result_int(context, result);
  }

void registerStringExtensions(sqlite3* db) {
  sqlite3_create_function(db,
                          "split",
                          3,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          tokenStringSplitFunc,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "regex_split",
                          3,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          regexStringSplitFunc,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "inet_aton",
                          1,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          ip4StringToDecimalFunc,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "version_less",
                          2,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          versionLessFunc,
                          nullptr,
                          nullptr);
}
} // namespace osquery
