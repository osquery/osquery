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
void testAggrTypeToStringAndBack(const monitoring::PreAggregationType& aggrType,
                                 const std::string& aggrTypeStrRepr) {
  auto str = to<std::string>(aggrType);
  EXPECT_EQ(str, aggrTypeStrRepr);

  auto bRet = tryTo<monitoring::PreAggregationType>(str);
  EXPECT_FALSE(bRet.isError());
  EXPECT_EQ(bRet.get(), aggrType);
}
} // namespace

GTEST_TEST(NumericMonitoringTests, PreAggregationTypeToStringAndBack) {
  testAggrTypeToStringAndBack(monitoring::PreAggregationType::None, "none");
  testAggrTypeToStringAndBack(monitoring::PreAggregationType::Sum, "sum");
  testAggrTypeToStringAndBack(monitoring::PreAggregationType::Min, "min");
  testAggrTypeToStringAndBack(monitoring::PreAggregationType::Max, "max");
}

GTEST_TEST(NumericMonitoringTests, PreAggregationTypeToStringRecall) {
  // let's make sure we have string representation for every PreAggregationType
  using UnderType = std::underlying_type<monitoring::PreAggregationType>::type;
  const auto upper_limit = static_cast<UnderType>(
      monitoring::PreAggregationType::InvalidTypeUpperLimit);
  for (auto i = UnderType{}; i < upper_limit; ++i) {
    auto e = static_cast<monitoring::PreAggregationType>(i);
    EXPECT_FALSE(to<std::string>(e).empty());
  }
}

} // namespace osquery
