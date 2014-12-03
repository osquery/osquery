// Copyright 2004-present Facebook. All Rights Reserved.

#include <gtest/gtest.h>
#include <glog/logging.h>

#include <osquery/devtools.h>

namespace osquery {

class PrinterTests : public testing::Test {
 public:
  QueryData q;
  std::vector<std::string> order;
  void SetUp() {
    order = {"name", "age", "favorite_food", "lucky_number"};
    q = {
        {
         {"name", "Mike Jones"},
         {"age", "39"},
         {"favorite_food", "mac and cheese"},
         {"lucky_number", "1"},
        },
        {
         {"name", "John Smith"},
         {"age", "44"},
         {"favorite_food", "peanut butter and jelly"},
         {"lucky_number", "2"},
        },
        {
         {"name", "Doctor Who"},
         {"age", "2000"},
         {"favorite_food", "fish sticks and custard"},
         {"lucky_number", "11"},
        },
    };
  }
};

TEST_F(PrinterTests, test_compute_query_data_lengths) {
  auto results = computeQueryDataLengths(q);
  std::map<std::string, int> expected = {
      {"name", 10}, {"age", 4}, {"favorite_food", 23}, {"lucky_number", 12},
  };
  EXPECT_EQ(results, expected);
}

TEST_F(PrinterTests, test_generate_separator) {
  auto results = generateSeparator(computeQueryDataLengths(q), order);
  auto expected =
      "+------------+------+-------------------------+--------------+\n";
  EXPECT_EQ(results, expected);
}

TEST_F(PrinterTests, test_generate_separator_2) {
  auto results =
      generateSeparator(computeQueryDataLengths(q),
                        {"lucky_number", "age", "name", "favorite_food"});
  auto expected =
      "+--------------+------+------------+-------------------------+\n";
  EXPECT_EQ(results, expected);
}

TEST_F(PrinterTests, test_generate_header) {
  auto results = generateHeader(computeQueryDataLengths(q), order);
  auto expected =
      "| name       | age  | favorite_food           | lucky_number |\n";
  EXPECT_EQ(results, expected);
}

TEST_F(PrinterTests, test_generate_header_2) {
  auto results =
      generateHeader(computeQueryDataLengths(q),
                     {"lucky_number", "age", "name", "favorite_food"});
  auto expected =
      "| lucky_number | age  | name       | favorite_food           |\n";
  EXPECT_EQ(results, expected);
}

TEST_F(PrinterTests, test_generate_row) {
  auto results = generateRow(q.back(), computeQueryDataLengths(q), order);
  auto expected =
      "| Doctor Who | 2000 | fish sticks and custard | 11           |\n";
  EXPECT_EQ(results, expected);
}

TEST_F(PrinterTests, test_generate_row_2) {
  auto results = generateRow(q.back(),
                             computeQueryDataLengths(q),
                             {"lucky_number", "age", "name", "favorite_food"});
  auto expected =
      "| 11           | 2000 | Doctor Who | fish sticks and custard |\n";
  EXPECT_EQ(results, expected);
}

TEST_F(PrinterTests, test_beautify) {
  auto result = beautify(q, order);
  std::string expected = R"(
+------------+------+-------------------------+--------------+
| name       | age  | favorite_food           | lucky_number |
+------------+------+-------------------------+--------------+
| Mike Jones | 39   | mac and cheese          | 1            |
| John Smith | 44   | peanut butter and jelly | 2            |
| Doctor Who | 2000 | fish sticks and custard | 11           |
+------------+------+-------------------------+--------------+
)";
  EXPECT_EQ(result, expected);
}

TEST_F(PrinterTests, test_unicode) {
  QueryData augmented = {
      {
       {"name", "Mike Jones"},
       {"age", "39"},
       {"favorite_food", "mac and cheese"},
       {"lucky_number", "1"},
      },
      {
       {"name", "Àlex Smith"},
       {"age", "44"},
       {"favorite_food", "peanut butter and jelly"},
       {"lucky_number", "2"},
      },
      {
       {"name", "Doctor Who"},
       {"age", "2000"},
       {"favorite_food", "fish sticks and custard"},
       {"lucky_number", "11"},
      },
  };
  auto result = beautify(augmented, order);
  std::string expected = R"(
+------------+------+-------------------------+--------------+
| name       | age  | favorite_food           | lucky_number |
+------------+------+-------------------------+--------------+
| Mike Jones | 39   | mac and cheese          | 1            |
| Àlex Smith | 44   | peanut butter and jelly | 2            |
| Doctor Who | 2000 | fish sticks and custard | 11           |
+------------+------+-------------------------+--------------+
)";
  EXPECT_EQ(result, expected);
}
}

int main(int argc, char* argv[]) {
  testing::InitGoogleTest(&argc, argv);
  google::InitGoogleLogging(argv[0]);
  return RUN_ALL_TESTS();
}
