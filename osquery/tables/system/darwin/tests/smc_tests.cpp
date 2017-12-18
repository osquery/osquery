/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/tests/test_util.h"

namespace osquery {
namespace tables {

void genTemperature(const Row &row, QueryData &results);
void genPower(const Row &row, QueryData &results);

class SmcTests : public testing::Test {};

TEST_F(SmcTests, test_gen_temperature) {
  QueryData results;
  // Generate a set of results/single row using an example smc temperature key.
  Row param = {
      {"key", "TC0E"},   {"type", "sp78"}, {"size", "2"},
      {"value", "3dd0"}, {"hidden", "0"},
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
  for (const auto &column : expected) {
    EXPECT_EQ(results[0][column.first], column.second);
  }
}

TEST_F(SmcTests, test_gen_power) {
  QueryData results;
  // Generate a set of results/single row using an example smc power key.
  Row param = {
      {"key", "PC1R"},   {"type", "sp78"}, {"size", "2"},
      {"value", "05a9"}, {"hidden", "0"},
  };
  genPower(param, results);

  Row expected = {
      {"key", "PC1R"}, {"name", "CPU Rail"}, {"value", "4.66"},
  };

  // We could compare the entire map, but iterating the columns will produce
  // better error text as most likely parsing for a certain column/type changed.
  for (const auto &column : expected) {
    EXPECT_EQ(results[0][column.first], column.second);
  }
}
}
}
