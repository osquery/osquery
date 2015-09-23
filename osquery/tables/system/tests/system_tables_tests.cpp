/*
 *  Copyright (c) 2014, Facebook, Inc.
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

QueryData genOSVersion(QueryContext& context);

class SystemsTablesTests : public testing::Test {};

TEST_F(SystemsTablesTests, test_os_version) {
  QueryContext context;
  auto result = genOSVersion(context);
  EXPECT_EQ(result.size(), 1);

  // Make sure major and minor contain data (a missing value of -1 is an error).
  EXPECT_FALSE(result[0]["major"].empty());
  EXPECT_FALSE(result[0]["minor"].empty());

  // The OS name should be filled in too.
  EXPECT_FALSE(result[0]["name"].empty());
}
}
}
