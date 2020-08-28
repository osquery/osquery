/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include "osquery/core/system.h"

namespace osquery {

class UUIDTests : public testing::Test {};

TEST_F(UUIDTests, test_invalid_uuid) {
  std::string uuid = "10000000-0000-8000-0040-000000000000";

  EXPECT_TRUE(isPlaceholderHardwareUUID(uuid));
}

TEST_F(UUIDTests, test_valid_uuid) {
  std::string uuid = "226e380e-67d1-4214-9868-5383a79af0b8";

  EXPECT_FALSE(isPlaceholderHardwareUUID(uuid));
}

} // namespace osquery
