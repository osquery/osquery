/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/devtools/devtools.h>
#include <osquery/logger/logger.h>

namespace osquery {

class PrinterTests : public testing::Test {
 public:
  QueryData q;
  std::vector<std::string> order;
  void SetUp() {
    order = {"name", "age", "food", "number"};
    q = {
        {
            {"name", "Mike Jones"},
            {"age", "39"},
            {"food", "mac and cheese"},
            {"number", "1"},
        },
        {
            {"name", "John Smith"},
            {"age", "44"},
            {"food", "peanut butter and jelly"},
            {"number", "2"},
        },
        {
            {"name", "Doctor Who"},
            {"age", "2000"},
            {"food", "fish sticks and custard"},
            {"number", "11"},
        },
    };
  }
};

TEST_F(PrinterTests, test_compute_query_data_lengths) {
  std::map<std::string, size_t> lengths;
  for (const auto& row : q) {
    computeRowLengths(row, lengths);
  }

  // Check that all value lengths were maxed.
  std::map<std::string, size_t> expected = {
      {"name", 10}, {"age", 4}, {"food", 23}, {"number", 2}};
  EXPECT_EQ(lengths, expected);

  // Then compute lengths of column names.
  computeRowLengths(q.front(), lengths, true);
  expected = {{"name", 10}, {"age", 4}, {"food", 23}, {"number", 6}};
  EXPECT_EQ(lengths, expected);
}

TEST_F(PrinterTests, test_generate_separator) {
  std::map<std::string, size_t> lengths;
  for (const auto& row : q) {
    computeRowLengths(row, lengths);
  }

  auto results = generateToken(lengths, order);
  auto expected = "+------------+------+-------------------------+----+\n";
  EXPECT_EQ(results, expected);
}

TEST_F(PrinterTests, test_generate_header) {
  std::map<std::string, size_t> lengths;
  for (const auto& row : q) {
    computeRowLengths(row, lengths);
  }

  auto results = generateHeader(lengths, order);
  auto expected = "| name       | age  | food                    | number |\n";
  EXPECT_EQ(results, expected);
}

TEST_F(PrinterTests, test_generate_row) {
  std::map<std::string, size_t> lengths;
  for (const auto& row : q) {
    computeRowLengths(row, lengths);
  }

  auto results = generateRow(q.front(), lengths, order);
  auto expected = "| Mike Jones | 39   | mac and cheese          | 1  |\n";
  EXPECT_EQ(results, expected);
}

TEST_F(PrinterTests, test_unicode) {
  Row r = {{"name", "Àlex Smith"}};
  std::map<std::string, size_t> lengths;
  computeRowLengths(r, lengths);

  std::map<std::string, size_t> expected = {{"name", 10}};
  EXPECT_EQ(lengths, expected);
}
} // namespace osquery
