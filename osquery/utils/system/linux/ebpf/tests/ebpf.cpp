/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/utils/system/linux/ebpf/ebpf.h>

namespace osquery {
namespace {

class EbpfTests : public testing::Test {};

TEST_F(EbpfTests, isSupportedBySystem) {
  auto const exp = ebpf::isSupportedBySystem();
  ASSERT_TRUE(exp.isValue()) << exp.getError().getMessage();
}

TEST_F(EbpfTests, sysEbpf_null_attr) {
  auto const exp = ebpf::syscall(BPF_MAP_CREATE, nullptr);
  ASSERT_TRUE(exp.isError());
  ASSERT_EQ(exp.getErrorCode(), PosixError::FAULT);
}

TEST_F(EbpfTests, sysEbpf_create_map) {
  auto const is_supported_exp = ebpf::isSupportedBySystem();
  EXPECT_TRUE(is_supported_exp.isValue())
      << is_supported_exp.getError().getMessage();
  if (is_supported_exp.get()) {
    union bpf_attr attr;
    memset(&attr, 0, sizeof(union bpf_attr));
    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = 4;
    attr.value_size = 4;
    attr.max_entries = 12;
    auto exp_bpf = ebpf::syscall(BPF_MAP_CREATE, &attr);
    ASSERT_TRUE(exp_bpf.isValue());
    ASSERT_GE(exp_bpf.get(), 0);
  }
}

} // namespace
} // namespace osquery
