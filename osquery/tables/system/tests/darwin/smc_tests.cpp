/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

namespace osquery {
namespace tables {

void genTemperature(const Row &row, QueryData &results);
void genPower(const Row &row, QueryData &results);

struct TestData {
  std::string type;
  std::string size;
  std::string value;
  std::string celcius;
  std::string fahrenheit;
};

// Test data for temperature conversion tests.
const TestData TestVals[] = {
    {"flt", "4", "9899e941", "29.2", "84.6"},
    {"flt", "4", "000080c0", "-4.0", "24.8"},
    {"ioft", "8", "00001d0000000000", "29.0", "84.2"},
    {"fp1f", "2", "3dd0", "0.5", "32.9"},
    {"fp2e", "2", "3dd0", "1.0", "33.7"},
    {"fp3d", "2", "3dd0", "1.9", "35.5"},
    {"fp4c", "2", "3dd0", "3.9", "39.0"},
    {"fp5b", "2", "3dd0", "7.7", "45.9"},
    {"fp6a", "2", "3dd0", "15.5", "59.8"},
    {"fp79", "2", "3dd0", "30.9", "87.6"},
    {"fp88", "2", "3dd0", "61.8", "143.3"},
    {"fpa6", "2", "3dd0", "247.2", "477.1"},
    {"fpc4", "2", "3dd0", "989.0", "1812.2"},
    {"fpe2", "2", "3dd0", "3956.0", "7152.8"},
    {"sp1e", "2", "3dd0", "1.0", "33.7"},
    {"sp2d", "2", "3dd0", "1.9", "35.5"},
    {"sp3c", "2", "3dd0", "3.9", "39.0"},
    {"sp4b", "2", "3dd0", "7.7", "45.9"},
    {"sp5a", "2", "3dd0", "15.5", "59.8"},
    {"sp69", "2", "3dd0", "30.9", "87.6"},
    {"sp78", "2", "3dd0", "61.8", "143.3"},
    {"sp78", "2", "ffc0", "-0.2", "31.6"},
    {"sp87", "2", "3dd0", "123.6", "254.5"},
    {"sp96", "2", "3dd0", "247.2", "477.1"},
    {"spa5", "2", "3dd0", "494.5", "922.1"},
    {"spb4", "2", "3dd0", "989.0", "1812.2"},
    {"spf0", "2", "3dd0", "15824.0", "28515.2"},
    {"ui8", "1", "41", "65.0", "149.0"},
    {"ui16", "2", "4141", "16705.0", "30101.0"},
    {"ui32", "4", "41414141", "1094795585.0", "1970632085.0"},
    {"ui64",
     "8",
     "4141414141414141",
     "4702111234474983424.0",
     "8463800222054970368.0"},
    {"si8", "1", "F0", "-16.0", "3.2"},
    {"si16", "2", "F0F0", "-3856.0", "-6908.8"},
    {"si32", "4", "F0F0F0F0", "-252645136.0", "-454761212.8"},
    {"si64",
     "8",
     "F0F0F0F0F0F0F0F0",
     "-1085102592571150080.0",
     "-1953184666628070144.0"},
};

class SmcTests : public ::testing::TestWithParam<TestData> {};

TEST_P(SmcTests, test_gen_temperature) {
  QueryData results;

  const auto& testVal = GetParam();
  Row param = {
      {"key", "TC0E"},
      {"type", testVal.type},
      {"size", testVal.size},
      {"value", testVal.value},
      {"hidden", "0"},
  };
  genTemperature(param, results);

  Row expected = {
      {"key", "TC0E"},
      {"name", "CPU 1"},
      {"celsius", testVal.celcius},
      {"fahrenheit", testVal.fahrenheit},
  };

  // We could compare the entire map, but iterating the columns will produce
  // better error text as most likely parsing for a certain column/type changed.
  for (const auto &column : expected) {
    EXPECT_EQ(results[0][column.first], column.second);
  }
}

INSTANTIATE_TEST_SUITE_P(
    SmcTestsConversionTests, // This can be any name you like
    SmcTests, // The fixture you defined
    ::testing::ValuesIn(TestVals));

TEST_F(SmcTests, test_gen_power) {
  QueryData results;
  // Generate a set of results/single row using an example smc power key.
  Row param = {
      {"key", "PC1R"},   {"type", "sp78"}, {"size", "2"},
      {"value", "05a9"}, {"hidden", "0"},
  };
  genPower(param, results);

  Row expected = {
      {"key", "PC1R"},
      {"name", "CPU Rail"},
      {"value", "5.66"},
  };

  // We could compare the entire map, but iterating the columns will produce
  // better error text as most likely parsing for a certain column/type changed.
  for (const auto &column : expected) {
    EXPECT_EQ(results[0][column.first], column.second);
  }
}
}
}
