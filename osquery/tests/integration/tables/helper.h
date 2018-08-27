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

class DataCheck {
 public:
  virtual ~DataCheck() = default;
  virtual bool validate(std::string string) = 0;
};

class IntMinMaxCheck : public DataCheck {
 public:
  explicit IntMinMaxCheck(int min, int max) : min_(min), max_(max){};
  virtual ~IntMinMaxCheck() = default;
  virtual bool validate(std::string string) override;

 private:
  const int min_;
  const int max_;
};

class SpecificValuesCheck : public DataCheck {
 public:
  explicit SpecificValuesCheck(std::initializer_list<std::string> list)
      : set_(list) {}
  virtual ~SpecificValuesCheck() = default;
  virtual bool validate(std::string string) override;

 private:
  const std::unordered_set<std::string> set_;
};

class IntegrationTableTest : public ::testing::Test {
 protected:
  enum {
    NormalType = 0 << 0,
    IntType = 1 << 0,

    NonEmpty = 1 << 1,
    NonNull = 1 << 2,
    NonNegative = 1 << 3,
    NonZero = 1 << 4,
    FileOnDisk = 1 << 5,
    DirectoryOnDisk = 1 << 6,
    ValidUUID = 1 << 7,
    MD5 = 1 << 8,
    SHA256 = 1 << 9,
    SHA1 = 1 << 10,
    Bool = 1 << 11,

    NonNegativeInt = IntType | NonEmpty | NonNull | NonNegative,
    NonEmptyString = NonEmpty | NormalType | NonNull,
  };

  using ValidatatioDataType = boost::variant<int, std::shared_ptr<DataCheck>>;
  using ValidatatioMap = std::unordered_map<std::string, ValidatatioDataType>;

  virtual void SetUp() {}

  virtual void TearDown() {}

  QueryData execute_query(std::string query);
  static bool validate_row(const Row& row,
                           const ValidatatioMap& validation_map);
  static bool validate_rows(const std::vector<Row>& rows,
                            const ValidatatioMap& validation_map);
  static bool validate_value_using_flags(const std::string& value, int flags);
  static bool is_valid_hex(const std::string& value);
};

} // namespace osquery
