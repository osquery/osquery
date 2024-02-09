/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/utils/darwin/system_profiler.h>

namespace osquery {

class DarwinSystemProfilerTests : public testing::Test {};

TEST_F(DarwinSystemProfilerTests, test_getSystemProfilerReport) {
  NSDictionary* __autoreleasing result;
  Status status = getSystemProfilerReport("SPEthernetDataType", result);
  EXPECT_TRUE(status.ok())
  EXPECT_NE([result count], 0U);
}

} // namespace osquery