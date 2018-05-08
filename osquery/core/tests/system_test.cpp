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

#include "osquery/system.h"

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
