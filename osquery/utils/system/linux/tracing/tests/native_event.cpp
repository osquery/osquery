/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
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
