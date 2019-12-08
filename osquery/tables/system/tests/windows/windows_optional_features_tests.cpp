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

#include <stdint.h>
#include <string>

#include <osquery/sql.h>

#include "osquery/tests/test_util.h"

namespace osquery {
namespace tables {

class WinOptFeaturesTablesTest : public testing::Test {};

extern std::string getDismPackageFeatureStateName(uint32_t state);

/*
 * Basic sanity check on function that provides a name
 * for InstallState.  We only know values 1 through 3.
 * All other values should return Unknown.
 */
TEST_F(WinOptFeaturesTablesTest, get_state_name) {
  EXPECT_EQ("Unknown", getDismPackageFeatureStateName(4));
  EXPECT_EQ("Unknown", getDismPackageFeatureStateName(999998));
  EXPECT_EQ("Unknown", getDismPackageFeatureStateName(0));
  EXPECT_EQ("Enabled", getDismPackageFeatureStateName(1));
  EXPECT_EQ("Disabled", getDismPackageFeatureStateName(2));
  EXPECT_EQ("Absent", getDismPackageFeatureStateName(3));
}
} // namespace tables
} // namespace osquery
