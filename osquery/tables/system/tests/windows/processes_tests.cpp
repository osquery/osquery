/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/tables/system/windows/processes.h>

namespace osquery {
namespace tables {

class ClampPebReadLengthTest : public ::testing::Test {};

TEST_F(ClampPebReadLengthTest, zero_length_passes_through) {
  EXPECT_EQ(static_cast<SIZE_T>(0), clampPebReadLength(0, 8192));
}

TEST_F(ClampPebReadLengthTest, length_below_buffer_unchanged) {
  EXPECT_EQ(static_cast<SIZE_T>(100), clampPebReadLength(100, 8192));
}

TEST_F(ClampPebReadLengthTest, length_equal_to_buffer_unchanged) {
  EXPECT_EQ(static_cast<SIZE_T>(8192), clampPebReadLength(8192, 8192));
}

// GHSA-4r78-6hg6-33gg regression: a malicious process can set its own PEB
// CommandLine.Length / CurrentDirectoryPath.Length up to USHORT max (65535).
// The destination buffer is 4096 wchar_t = 8192 bytes. Without clamping,
// ReadProcessMemory would overflow the heap buffer by ~57KB.
TEST_F(ClampPebReadLengthTest, attacker_max_length_clamped_to_buffer) {
  EXPECT_EQ(static_cast<SIZE_T>(8192), clampPebReadLength(65535, 8192));
}

TEST_F(ClampPebReadLengthTest, one_over_buffer_clamped) {
  EXPECT_EQ(static_cast<SIZE_T>(8192), clampPebReadLength(8193, 8192));
}

TEST_F(ClampPebReadLengthTest, smaller_buffer_clamps_correctly) {
  EXPECT_EQ(static_cast<SIZE_T>(100), clampPebReadLength(200, 100));
  EXPECT_EQ(static_cast<SIZE_T>(50), clampPebReadLength(50, 100));
}

TEST_F(ClampPebReadLengthTest, buffer_larger_than_ushort_max_unchanged) {
  // dest_size > USHORT max — peb_length always fits, no clamping needed.
  EXPECT_EQ(static_cast<SIZE_T>(65535),
            clampPebReadLength(65535, static_cast<SIZE_T>(100000)));
}

} // namespace tables
} // namespace osquery
