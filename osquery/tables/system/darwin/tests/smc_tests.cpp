/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <gtest/gtest.h>

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/test_util.h"

namespace osquery {
namespace tables {

void genTemperature(const Row &row,
                    QueryData &results);
void genVoltage(const Row &row,
                QueryData &results);

class SmcTests : public testing::Test {};

TEST_F(SmcTests, test_gen_temperature) {
  QueryData results;
  // Generate a set of results/single row using an example smc temperature key.
  Row param = {
    {"key", "TC0E"},
    {"type", "sp78"},
    {"size", "2"},
    {"value", "3dd0"},
    {"hidden", "0"},
  };
  genTemperature(param, results);

  Row expected = {
      {"key", "TC0E"},
      {"name", "CPU 1"},
      {"celsius", "60.8"},
      {"fahrenheit", "141.5"},
  };

  // We could compare the entire map, but iterating the columns will produce
  // better error text as most likely parsing for a certain column/type changed.
  for (const auto& column : expected) {
    EXPECT_EQ(results[0][column.first], column.second);
  }
}

TEST_F(SmcTests, test_gen_voltage) {
  QueryData results;
  // Generate a set of results/single row using an example smc voltage key.
  Row param = {
    {"key", "VC0C"},
    {"type", "sp5a"},
    {"size", "2"},
    {"value", "035b"},
    {"hidden", "0"},
  };
  genVoltage(param, results);

  Row expected = {
      {"key", "VC0C"},
      {"name", "CPU Core 1"},
      {"value", "0.84"},
  };

  // We could compare the entire map, but iterating the columns will produce
  // better error text as most likely parsing for a certain column/type changed.
  for (const auto& column : expected) {
    EXPECT_EQ(results[0][column.first], column.second);
  }
}

}
}
