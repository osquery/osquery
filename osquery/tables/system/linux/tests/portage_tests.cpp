/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <pwd.h>

#include <gtest/gtest.h>

#include <osquery/core.h>
#include <osquery/logger.h>
#include <osquery/system.h>

#include "osquery/tests/test_util.h"

namespace osquery {
namespace tables {
std::pair<std::string, std::string> portageSplitPackageVersion(
    const std::string& pkgStr);

class PortageTests : public testing::Test {};

TEST_F(PortageTests, portageSplitPackageVersion_specific_version) {
  auto result = portageSplitPackageVersion("=sys-kernel/gentoo-sources-4.9.0");

  ASSERT_EQ(result.first, "sys-kernel/gentoo-sources");
  ASSERT_EQ(result.second, "4.9.0");
}

TEST_F(PortageTests, portageSplitPackageVersion_less_or_equal_version) {
  auto result =
      portageSplitPackageVersion("<=sys-kernel/gentoo-sources-4.9.0-r1");

  ASSERT_EQ(result.first, "sys-kernel/gentoo-sources");
  ASSERT_EQ(result.second, "<=4.9.0-r1");
}

TEST_F(PortageTests, portageSplitPackageVersion_greater_or_equal_version) {
  auto result =
      portageSplitPackageVersion(">=sys-kernel/gentoo-sources-4.9.0_alpha2");

  ASSERT_EQ(result.first, "sys-kernel/gentoo-sources");
  ASSERT_EQ(result.second, ">=4.9.0_alpha2");
}

TEST_F(PortageTests, portageSplitPackageVersion_no_version) {
  auto result = portageSplitPackageVersion("sys-kernel/gentoo-sources");

  ASSERT_EQ(result.first, "sys-kernel/gentoo-sources");
  ASSERT_EQ(result.second, "");
}
} // namespace tables
} // namespace osquery
