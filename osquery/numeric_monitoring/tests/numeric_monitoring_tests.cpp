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

#include <boost/filesystem.hpp>

#include <osquery/core/conversions.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/registry_factory.h>

#include <osquery/tests/test_util.h>

#include "include/osquery/numeric_monitoring.h"

namespace osquery {

namespace {
void testAggregationTypeSerialisation(
    const monitoring::AggregationType& aggrType,
    const std::string& aggrTypeStrRepr) {
  auto fRet = tryTo<std::string>(aggrType);
  EXPECT_FALSE(fRet.isError());
  EXPECT_EQ(fRet.get(), aggrTypeStrRepr);

  auto bRet = tryTo<monitoring::AggregationType>(aggrTypeStrRepr);
  EXPECT_FALSE(bRet.isError());
  EXPECT_EQ(bRet.get(), aggrType);
}
} // namespace

GTEST_TEST(NumericMonitoringTests, AggregationTypeToStringAndBack) {
  testAggregationTypeSerialisation(monitoring::AggregationType::None, "none");
  testAggregationTypeSerialisation(monitoring::AggregationType::Sum, "sum");
  testAggregationTypeSerialisation(monitoring::AggregationType::Min, "min");
  testAggregationTypeSerialisation(monitoring::AggregationType::Max, "max");
}

} // namespace osquery
