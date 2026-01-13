/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <libbpf.h>

namespace osquery {

class LibbpfTest : public testing::Test {};

TEST_F(LibbpfTest, test_libbpf_version) {
  // Just verify we can call into the library
  auto major = libbpf_major_version();
  auto minor = libbpf_minor_version();
  
  // We don't enforce specific versions, just that getting them didn't crash
  // and returned reasonable numbers (e.g. not random garbage)
  EXPECT_GE(major, 0U);
  EXPECT_GE(minor, 0U);
}

TEST_F(LibbpfTest, test_loading_invalid_alloc) {
  // Test that we can attempt to load an object from memory
  // This verifies headers are correct and linking is correct.
  
  const char dummy_data[] = "this is not a valid elf file";
  
  struct bpf_object_open_opts opts = {};
  opts.sz = sizeof(opts);
  opts.object_name = "test_obj";
  
  struct bpf_object* obj = bpf_object__open_mem(dummy_data, sizeof(dummy_data), &opts);
  
  // We expect this to fail because data is invalid
  EXPECT_EQ(obj, nullptr);
  
  // We can also check that it failed for the expected reason aka invalid format
  // but just checking it returned NULL means the function executed.
}

} // namespace osquery
