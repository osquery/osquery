/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <stdint.h>
#include <string>

#include <osquery/sql/sql.h>

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
