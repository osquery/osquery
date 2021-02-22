/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <assert.h>

#ifdef WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include <functional>
#include <regex>
#include <string>
#include <vector>

#include <osquery/core/flags.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/split.h>

#include <sqlite3.h>

namespace osquery {

HIDDEN_FLAG(
    uint32,
    regex_max_size,
    256,
    "Defines the maximum size in bytes of a regex that can be used with the "
    "regex_match and regex_split functions");

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
  // Exceptions are caught by the caller, as that's where the sql context is
  std::vector<std::string> result;

  if (token.size() > FLAGS_regex_max_size) {
    throw std::regex_error(std::regex_constants::error_complexity);
  }

  std::regex pattern = std::regex(token);
  std::sregex_token_iterator iter_begin(
      input.begin(), input.end(), pattern, -1);
  std::sregex_token_iterator iter_end;
  std::copy(iter_begin, iter_end, std::back_inserter(result));

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
    // Empty input string is an error
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
  try {
    callStringSplitFunc(context, argc, argv, regexSplit);
  } catch (const std::regex_error& e) {
    LOG(INFO) << "Invalid regex: " << e.what();
    sqlite3_result_error(context, "Invalid regex", -1);
  }
}

/**
 * @brief Regex match a string
 */
static void regexStringMatchFunc(sqlite3_context* context,
                                 int argc,
                                 sqlite3_value** argv) {
  // Ensure we have not-null values
  assert(argc == 3);
  if (SQLITE_NULL == sqlite3_value_type(argv[0]) ||
      SQLITE_NULL == sqlite3_value_type(argv[1]) ||
      SQLITE_NULL == sqlite3_value_type(argv[2])) {
    sqlite3_result_null(context);
    return;
  }

  const char* regex =
      reinterpret_cast<const char*>(sqlite3_value_text(argv[1]));

  if (regex == nullptr) {
    sqlite3_result_null(context);
    return;
  }

  // parse and verify input parameters
  const std::string input(
      reinterpret_cast<const char*>(sqlite3_value_text(argv[0])));
  std::smatch results;
  auto index = static_cast<size_t>(sqlite3_value_int(argv[2]));
  bool isMatchFound = false;

  if (strnlen(regex, FLAGS_regex_max_size) == FLAGS_regex_max_size &&
      regex[FLAGS_regex_max_size] != '\0') {
    std::string error = "Invalid regex: too big, max size is " +
                        std::to_string(FLAGS_regex_max_size) + " bytes";
    LOG(INFO) << error;
    sqlite3_result_error(context, error.c_str(), -1);
    return;
  }

  try {
    isMatchFound = std::regex_search(input, results, std::regex(regex));
  } catch (const std::regex_error& e) {
    LOG(INFO) << "Invalid regex: " << e.what();
    sqlite3_result_error(context, "Invalid regex", -1);
    return;
  }

  if (!isMatchFound) {
    sqlite3_result_null(context);
    return;
  }

  if (index >= results.size()) {
    sqlite3_result_null(context);
    return;
  }

  sqlite3_result_text(context,
                      results[index].str().c_str(),
                      static_cast<int>(results[index].str().size()),
                      SQLITE_TRANSIENT);
}

static void concatFunc(sqlite3_context* context,
                       std::string sep,
                       int starting,
                       int argc,
                       sqlite3_value** argv) {
  // Nothing to concat, early return
  if ((argc - starting) == 0) {
    return;
  }

  std::string output;

  for (auto i = starting; i < argc; i++) {
    if (SQLITE_NULL == sqlite3_value_type(argv[i])) {
      continue;
    }

    output.append(reinterpret_cast<const char*>(sqlite3_value_text(argv[i])));

    if (sep != "" && i + 1 < argc) {
      output.append(sep);
    }
  }

  // Give up if the output is so large it's length overflows int
  if (output.size() > std::numeric_limits<int>::max()) {
    sqlite3_result_error(context, "Too much data for concat_ws", -1);
    return;
  }

  sqlite3_result_text(context,
                      output.c_str(),
                      static_cast<int>(output.size()),
                      SQLITE_TRANSIENT);
}

/**
 * @brief Concatenate strings ignoring nulls
 */
static void concatStringFunc(sqlite3_context* context,
                             int argc,
                             sqlite3_value** argv) {
  concatFunc(context, "", 0, argc, argv);
}

/**
 * @brief Concatenate strings ignoring nulls, with separator
 */
static void concatWSStringFunc(sqlite3_context* context,
                               int argc,
                               sqlite3_value** argv) {
  // First arg is the separator. Error if not present
  if (argc == 0) {
    sqlite3_result_error(context, "Missing separator to concat_ws", -1);
    return;
  }

  const std::string sep =
      (SQLITE_NULL != sqlite3_value_type(argv[0]))
          ? reinterpret_cast<const char*>(sqlite3_value_text(argv[0]))
          : "";

  concatFunc(context, sep, 1, argc, argv);
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
                          "regex_match",
                          3,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          regexStringMatchFunc,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "concat",
                          -1,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          concatStringFunc,
                          nullptr,
                          nullptr);
  sqlite3_create_function(db,
                          "concat_ws",
                          -1,
                          SQLITE_UTF8 | SQLITE_DETERMINISTIC,
                          nullptr,
                          concatWSStringFunc,
                          nullptr,
                          nullptr);
}
} // namespace osquery
