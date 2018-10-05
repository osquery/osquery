/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <unordered_set>

#include <boost/variant.hpp>
#include <gtest/gtest.h>

#include <osquery/sql/sqlite_util.h>

namespace osquery {

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

class IntegrationTableTest : public ::testing::Test {
 protected:
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
    NonNegativeInt = IntType | NonEmpty | NonNull | (1 << 12),
    NonNegativeOrErrorInt = IntType | NonEmpty | NonNull | (1 << 13),
    NonEmptyString = NonEmpty | NormalType | NonNull,
  };

  using CustomCheckerType = std::function<bool(const std::string&)>;
  using ValidatatioDataType = boost::variant<int, CustomCheckerType>;
  using ValidatatioMap = std::unordered_map<std::string, ValidatatioDataType>;

  virtual void SetUp() {}

  virtual void TearDown() {}

  QueryData execute_query(std::string query);

  static void validate_row(const Row& row,
                           const ValidatatioMap& validation_map);
  static void validate_rows(const std::vector<Row>& rows,
                            const ValidatatioMap& validation_map);
  static bool validate_value_using_flags(const std::string& value, int flags);
  static bool is_valid_hex(const std::string& value);
};

} // namespace osquery
