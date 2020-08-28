/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <pwd.h>

#include <gtest/gtest.h>

#include <osquery/core/core.h>
#include <osquery/core/system.h>
#include <osquery/logger/logger.h>

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
