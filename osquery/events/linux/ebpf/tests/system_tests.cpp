
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include "osquery/events/linux/ebpf/system.h"

#include <osquery/tests/test_util.h>

#include <gtest/gtest.h>

namespace osquery {
namespace {

class EbpfSystemTests : public testing::Test {};

TEST_F(EbpfSystemTests, getKernelReleaseVersion) {
  auto const version = ebpf::impl::getKernelReleaseVersion();
  EXPECT_GE(version.major, 2);
}

} // namespace
} // namespace osquery
