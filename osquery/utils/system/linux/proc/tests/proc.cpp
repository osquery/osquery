/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/linux/proc/proc.h>

#include <gtest/gtest.h>

#include <sys/types.h>
#include <unistd.h>

namespace osquery {
namespace {

class LinuxProcTests : public testing::Test {};

TEST_F(LinuxProcTests, cmdline_1) {
  auto line = proc::cmdline(1);
  ASSERT_FALSE(line.empty());
}

TEST_F(LinuxProcTests, cmdline_self) {
  auto line = proc::cmdline(getpid());
  ASSERT_NE(line.find("osquery/utils/system/linux/proc/tests/proc_tests"),
            std::string::npos);
}

TEST_F(LinuxProcTests, cmdline_not_existing_pid) {
  ASSERT_TRUE(proc::cmdline(-1).empty());
  ASSERT_TRUE(proc::cmdline(0).empty());
  ASSERT_TRUE(proc::cmdline(-12).empty());
}

} // namespace
} // namespace osquery
