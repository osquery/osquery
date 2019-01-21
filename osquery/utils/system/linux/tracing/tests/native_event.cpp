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

#include <osquery/utils/system/linux/tracing/native_event.h>

namespace osquery {
namespace {

class NativeEventTests : public testing::Test {};

TEST_F(NativeEventTests, non_root_load_should_fail) {
  auto const exp = tracing::NativeEvent::load("syscalls/sys_enter_open");
  ASSERT_TRUE(exp.isError());
  ASSERT_EQ(exp.getErrorCode(), tracing::NativeEvent::Error::System);
}
} // namespace
} // namespace osquery
