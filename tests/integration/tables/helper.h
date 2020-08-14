/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <unordered_set>

#include <boost/variant.hpp>
#include <gtest/gtest.h>

#include <osquery/sql/sqlite_util.h>

namespace osquery {
namespace table_tests {

class IntMinMaxCheck final {
 public:
  explicit IntMinMaxCheck(int64_t min, int64_t max) : min_(min), max_(max){};
  bool operator()(const std::string& string) const;

 private:
  const int64_t min_;
  const int64_t max_;
};

class SpecificValuesCheck final {
 public:
  explicit SpecificValuesCheck(std::initializer_list<std::string> list)
      : set_(list) {}
  bool operator()(const std::string& string) const;

 private:
  const std::unordered_set<std::string> set_;
};

class CronValuesCheck final {
 public:
  explicit CronValuesCheck(int64_t min,
                           int64_t max,
                           std::unordered_set<std::string> values = {})
      : min_(min), max_(max), values_(std::move(values)){};
  bool operator()(const std::string& string) const;

 private:
  const int64_t min_;
  const int64_t max_;
  const std::unordered_set<std::string> values_;
};

bool verifyIpAddress(std::string const& value);

bool verifyEmptyStringOrIpAddress(std::string const& value);

bool verifyMacAddress(std::string const& value);

bool verifyUidGid(std::string const& value);

enum {
  NormalType = 0 << 0,
  IntType = 1 << 1,
  NonEmpty = 1 << 2,
  NonNull = 1 << 3,
  NonZero = 1 << 4,
  FileOnDisk = 1 << 5,
  DirectoryOnDisk = 1 << 6,
  ValidUUID = 1 << 7,
  MD5 = 1 << 8,
  SHA256 = 1 << 9,
  SHA1 = 1 << 10,
  Bool = 1 << 11,
  EmptyOk = 1 << 12,
  NullOk = 1 << 13,
  NonNegativeInt = IntType | NonEmpty | NonNull | (1 << 12),
  NonNegativeOrErrorInt = IntType | NonEmpty | NonNull | (1 << 13),
  NonEmptyString = NonEmpty | NormalType | NonNull,
  IntOrEmpty = IntType | EmptyOk | NullOk,
};

using CustomCheckerType = std::function<bool(const std::string&)>;
using ValidationDataType = boost::variant<int, CustomCheckerType>;
using ValidationMap = std::unordered_map<std::string, ValidationDataType>;

QueryData execute_query(std::string query);

void validate_row(const Row& row, const ValidationMap& validation_map);
void validate_rows(const std::vector<Row>& rows,
                   const ValidationMap& validation_map);
bool validate_value_using_flags(const std::string& value, int flags);
void validate_container_rows(
    const std::string& table_name,
    ValidationMap& validation_map,
    const std::string& sql_constraints = std::string());
bool is_valid_hex(const std::string& value);

void setUpEnvironment();

} // namespace table_tests
} // namespace osquery
