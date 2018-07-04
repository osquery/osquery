/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <limits>

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>

#include <osquery/core/conversions.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include <osquery/tests/test_util.h>

#include "include/osquery/numeric_monitoring.h"

namespace osquery {

namespace {
void testAggregationTypeToStringAndBack(
    const monitoring::AggregationType& aggrType,
    const std::string& aggrTypeStrRepr) {
  auto str = to<std::string>(aggrType);
  EXPECT_EQ(str, aggrTypeStrRepr);

  auto bRet = tryTo<monitoring::AggregationType>(str);
  EXPECT_FALSE(bRet.isError());
  EXPECT_EQ(bRet.get(), aggrType);
}
} // namespace

GTEST_TEST(NumericMonitoringTests, AggregationTypeToStringAndBack) {
  testAggregationTypeToStringAndBack(monitoring::AggregationType::None, "none");
  testAggregationTypeToStringAndBack(monitoring::AggregationType::Sum, "sum");
  testAggregationTypeToStringAndBack(monitoring::AggregationType::Min, "min");
  testAggregationTypeToStringAndBack(monitoring::AggregationType::Max, "max");
}

GTEST_TEST(NumericMonitoringTests, AggregationTypeToStringRecall) {
  // let's make sure we have string representation for every AggregationType
  for (int i = 0;
       i < static_cast<int>(monitoring::AggregationType::InvalidTypeUpperLimit);
       ++i) {
    auto e = static_cast<monitoring::AggregationType>(i);
    EXPECT_FALSE(to<std::string>(e).empty());
  }
}

} // namespace osquery
