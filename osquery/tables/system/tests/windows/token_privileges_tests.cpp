/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/tables/system/windows/token_privileges.h>

namespace osquery {
namespace tables {

class TokenPrivilegesTest : public testing::Test {};

TEST_F(TokenPrivilegesTest, se_debug_privilege_guard) {
  // Store the original state of the privilege so we can verify it remains
  // unchanged after the test
  SeDebugPrivState originalState = getDebugTokenPrivilegeState();

  // Create a guard and check that the privilege is enabled
  auto guard1 = std::make_unique<SeDebugPrivilegeGuard>();
  EXPECT_EQ(getDebugTokenPrivilegeState(), SeDebugPrivState::Enabled);
  EXPECT_EQ(guard1->refCount(), 1);

  // Create 10 more guards and check that the privilege remains enabled and
  // the ref count is correct
  std::vector<SeDebugPrivilegeGuard> guardVector(10);
  EXPECT_EQ(getDebugTokenPrivilegeState(), SeDebugPrivState::Enabled);
  EXPECT_EQ(guard1->refCount(), 11); // guard1 + 10 in the vector

  // Destroy the guards one by one and check that the privilege remains enabled
  // until the last guard is destroyed
  while (!guardVector.empty()) {
    guardVector.pop_back();
    EXPECT_EQ(getDebugTokenPrivilegeState(), SeDebugPrivState::Enabled);
    EXPECT_EQ(guard1->refCount(),
              static_cast<int>(guardVector.size()) +
                  1); // guard1 + remaining guards in the vector
  }

  // After all guards in the vector are destroyed, only guard1 should be active
  // and the privilege should still be enabled
  EXPECT_TRUE(guardVector.empty());
  EXPECT_EQ(getDebugTokenPrivilegeState(), SeDebugPrivState::Enabled);
  EXPECT_EQ(guard1->refCount(), 1); // Only guard1 should be active

  guard1.reset(); // Destroy the last guard

  // After all guards are destroyed, the privilege should be reset to its
  // original state
  EXPECT_EQ(getDebugTokenPrivilegeState(), originalState);
}

} // namespace tables
} // namespace osquery
