/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <chrono>

#include <gtest/gtest.h>

#include <osquery/utils/system/system.h>

namespace osquery {

class SystemTests : public testing::Test {};

TEST_F(SystemTests, test_self_resource_usage) {
  SelfResourceUsage before;
  ASSERT_TRUE(getSelfResourceUsage(before));
  EXPECT_GT(before.resident_size, 0U);

  // Burn some CPU so the user time moves by more than one scheduler tick.
  auto start = std::chrono::steady_clock::now();
  volatile std::uint64_t sink = 0;
  while (std::chrono::steady_clock::now() - start <
         std::chrono::milliseconds(200)) {
    sink += 1;
  }

  SelfResourceUsage after;
  ASSERT_TRUE(getSelfResourceUsage(after));
  EXPECT_GT(after.user_time_ms, before.user_time_ms);
  EXPECT_GE(after.system_time_ms, before.system_time_ms);
  EXPECT_GT(after.resident_size, 0U);
}

} // namespace osquery
