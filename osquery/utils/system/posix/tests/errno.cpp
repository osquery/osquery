/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include <string>

#include <gtest/gtest.h>

#include <osquery/utils/system/posix/errno.h>

namespace osquery {
namespace {

class PosixErrnoTests : public testing::Test {};

TEST_F(PosixErrnoTests, to) {
  EXPECT_EQ(PosixError::Unknown, to<PosixError>(0));
  EXPECT_EQ(PosixError::Unknown, to<PosixError>(-1));
  EXPECT_EQ(PosixError::Unknown, to<PosixError>(98765));
  EXPECT_EQ(PosixError::Unknown, to<PosixError>(987654));

  EXPECT_EQ(PosixError::PIPE, to<PosixError>(EPIPE));
  EXPECT_EQ(PosixError::DOM, to<PosixError>(EDOM));
  EXPECT_EQ(PosixError::RANGE, to<PosixError>(ERANGE));
  EXPECT_EQ(PosixError::T_BIG, to<PosixError>(E2BIG));
}

} // namespace
} // namespace osquery
