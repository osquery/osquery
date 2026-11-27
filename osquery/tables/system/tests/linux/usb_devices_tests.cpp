/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

#include <osquery/tables/system/linux/usb_devices.h>

namespace osquery {
namespace tables {

TEST(USBDevicesTests, parses_decimal_numbers) {
  const std::vector<std::pair<std::string, int>> test_cases = {
      {"0", 0},
      {"008", 8},
      {"009", 9},
      {"010", 10},
      {"011", 11},
      {std::to_string(std::numeric_limits<int>::max()),
       std::numeric_limits<int>::max()},
  };

  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(test_case.first);

    int number{42};
    EXPECT_TRUE(parseUSBDeviceNumber(test_case.first, number));
    EXPECT_EQ(test_case.second, number);
  }
}

TEST(USBDevicesTests, rejects_non_decimal_numbers_without_changing_output) {
  const auto out_of_range_number = std::to_string(
      static_cast<long long>(std::numeric_limits<int>::max()) + 1LL);

  const std::vector<std::string> test_cases = {
      "",
      "invalid",
      "010invalid",
      "0x10",
      " 8",
      "8 ",
      "+8",
      "-8",
      "+0",
      "-0",
      out_of_range_number,
  };

  for (const auto& test_case : test_cases) {
    SCOPED_TRACE(test_case);

    int number{42};
    EXPECT_FALSE(parseUSBDeviceNumber(test_case, number));
    EXPECT_EQ(42, number);
  }
}

TEST(USBDevicesTests, preserves_row_and_omits_only_malformed_number) {
  const auto out_of_range_number = std::to_string(
      static_cast<long long>(std::numeric_limits<int>::max()) + 1LL);

  const std::vector<std::string> malformed_values = {
      "invalid",
      "010invalid",
      "0x10",
      " 8",
      "8 ",
      "+8",
      "-8",
      "+0",
      "-0",
      out_of_range_number,
  };

  for (const auto& malformed_value : malformed_values) {
    SCOPED_TRACE(malformed_value);

    QueryData address_results;
    addUSBDeviceRow(address_results,
                    Row{{"model", "malformed address"}},
                    malformed_value,
                    "009");

    ASSERT_EQ(1U, address_results.size());
    EXPECT_EQ("malformed address", address_results[0].at("model"));
    EXPECT_EQ(0U, address_results[0].count("usb_address"));
    EXPECT_EQ("9", address_results[0].at("usb_port"));

    QueryData port_results;
    addUSBDeviceRow(
        port_results, Row{{"model", "malformed port"}}, "008", malformed_value);

    ASSERT_EQ(1U, port_results.size());
    EXPECT_EQ("malformed port", port_results[0].at("model"));
    EXPECT_EQ("8", port_results[0].at("usb_address"));
    EXPECT_EQ(0U, port_results[0].count("usb_port"));
  }

  QueryData results;
  addUSBDeviceRow(results,
                  Row{{"model", "both malformed"}},
                  "invalid address",
                  "invalid port");

  ASSERT_EQ(1U, results.size());
  EXPECT_EQ("both malformed", results[0].at("model"));
  EXPECT_EQ(0U, results[0].count("usb_address"));
  EXPECT_EQ(0U, results[0].count("usb_port"));
}

TEST(USBDevicesTests, canonicalizes_padded_numbers_in_preserved_row) {
  QueryData results;
  addUSBDeviceRow(results, Row{{"model", "padded numbers"}}, "008", "009");

  ASSERT_EQ(1U, results.size());
  EXPECT_EQ("padded numbers", results[0].at("model"));
  EXPECT_EQ("8", results[0].at("usb_address"));
  EXPECT_EQ("9", results[0].at("usb_port"));
}

TEST(USBDevicesTests, omits_row_when_number_property_is_missing) {
  QueryData results;
  addUSBDeviceRow(results, Row{}, "", "009");
  addUSBDeviceRow(results, Row{}, "008", "");

  EXPECT_TRUE(results.empty());
}

} // namespace tables
} // namespace osquery
