/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/utils/system/linux/ebpf/program.h>
#include <osquery/utils/system/linux/ebpf/ebpf.h>

#include <osquery/logger/logger.h>

#include <gtest/gtest.h>

namespace osquery {
namespace {

class EbpfProgramTests : public testing::Test {};

bool const kDebug =
#ifndef NDEBUG
    true;
#else
    false;
#endif

TEST_F(EbpfProgramTests, empty_debug) {
  auto const ebpf_exp = ebpf::isSupportedBySystem();
  EXPECT_TRUE(ebpf_exp.isValue()) << ebpf_exp.getError().getMessage();
  if (!ebpf_exp.get()) {
    LOG(WARNING) << "This system does not support eBPF of required vesion, "
                    "test will be skipped";
    return;
  }
  auto program_exp = ebpf::Program::load({}, BPF_PROG_TYPE_KPROBE, kDebug);
  ASSERT_TRUE(program_exp.isError());
  ASSERT_EQ(program_exp.getErrorCode(), ebpf::Program::Error::Unknown);
}

} // namespace
} // namespace osquery
