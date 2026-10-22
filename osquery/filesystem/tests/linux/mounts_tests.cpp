/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <atomic>
#include <chrono>
#include <stdexcept>
#include <thread>

#include <gtest/gtest.h>

#include <osquery/filesystem/linux/mounts.h>

namespace osquery {
namespace {
// The in-flight tracker in getStatFsInfoWithTimeout is a process-global
// singleton with no reset, and a hung probe stays in-flight across tests. Each
// test that hangs a probe must therefore use a path no other test hangs, or the
// later test is silently skipped instead of exercising the path it means to.
class LinuxMounts : public testing::Test {};

MountInformation::StatFsInfo makeStatFsInfo() {
  MountInformation::StatFsInfo info = {};
  info.block_size = 4096;
  info.block_count = 100;
  return info;
}

boost::optional<MountInformation::StatFsInfo> some() {
  return boost::optional<MountInformation::StatFsInfo>(makeStatFsInfo());
}

boost::optional<MountInformation::StatFsInfo> none() {
  return boost::none;
}

TEST_F(LinuxMounts, statfs_returns_producer_result_when_fast) {
  auto results = getStatFsInfoWithTimeout(
      {"/fast"}, std::chrono::seconds(5), [](const std::string&) {
        return some();
      });

  ASSERT_EQ(results.size(), 1U);
  ASSERT_TRUE(results[0] != boost::none);
  EXPECT_EQ(results[0]->block_size, 4096U);
  EXPECT_EQ(results[0]->block_count, 100U);
}

TEST_F(LinuxMounts, statfs_passes_through_producer_failure) {
  auto results = getStatFsInfoWithTimeout(
      {"/broken"}, std::chrono::seconds(5), [](const std::string&) {
        return none();
      });

  ASSERT_EQ(results.size(), 1U);
  EXPECT_TRUE(results[0] == boost::none);
}

// A producer that never returns (malicious/hung FUSE) must not block the
// caller. The call must come back near the timeout, not the hang.
TEST_F(LinuxMounts, statfs_does_not_block_on_hang) {
  const auto timeout = std::chrono::milliseconds(100);
  const auto hang = std::chrono::seconds(3);

  auto start = std::chrono::steady_clock::now();
  auto results =
      getStatFsInfoWithTimeout({"/hung"}, timeout, [hang](const std::string&) {
        std::this_thread::sleep_for(hang);
        return some();
      });
  auto elapsed = std::chrono::steady_clock::now() - start;

  ASSERT_EQ(results.size(), 1U);
  EXPECT_TRUE(results[0] == boost::none);
  EXPECT_LT(elapsed, hang);
}

// A hung mount must not truncate results for the healthy mounts probed
// alongside it: the fast mount keeps its data, the hung one degrades to
// boost::none, and the call returns near the deadline.
TEST_F(LinuxMounts, statfs_hang_does_not_truncate_healthy_mounts) {
  const auto timeout = std::chrono::milliseconds(200);

  auto start = std::chrono::steady_clock::now();
  auto results = getStatFsInfoWithTimeout(
      {"/fast", "/hung-mixed"}, timeout, [](const std::string& path) {
        if (path == "/hung-mixed") {
          std::this_thread::sleep_for(std::chrono::seconds(3));
        }
        return some();
      });
  auto elapsed = std::chrono::steady_clock::now() - start;

  ASSERT_EQ(results.size(), 2U);
  ASSERT_TRUE(results[0] != boost::none);
  EXPECT_EQ(results[0]->block_size, 4096U);
  EXPECT_TRUE(results[1] == boost::none);
  EXPECT_LT(elapsed, std::chrono::seconds(1));
}

// A throwing producer must be contained (not escape the detached thread and
// call std::terminate) and reported as boost::none.
TEST_F(LinuxMounts, statfs_contains_producer_exception) {
  auto results = getStatFsInfoWithTimeout(
      {"/throws"}, std::chrono::seconds(5), [](const std::string&) {
        throw std::runtime_error("boom");
        return some();
      });

  ASSERT_EQ(results.size(), 1U);
  EXPECT_TRUE(results[0] == boost::none);
}

// N hung mounts must be bounded by a single timeout, not N*timeout: the probes
// run concurrently.
TEST_F(LinuxMounts, statfs_hung_mounts_bounded_by_single_timeout) {
  const auto timeout = std::chrono::milliseconds(200);
  const std::vector<std::string> paths{
      "/hung0", "/hung1", "/hung2", "/hung3", "/hung4"};

  auto start = std::chrono::steady_clock::now();
  auto results =
      getStatFsInfoWithTimeout(paths, timeout, [](const std::string&) {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        return some();
      });
  auto elapsed = std::chrono::steady_clock::now() - start;

  ASSERT_EQ(results.size(), paths.size());
  for (const auto& result : results) {
    EXPECT_TRUE(result == boost::none);
  }
  EXPECT_LT(elapsed, paths.size() * timeout);
}

// Distinct occurrences of the same mount path share one probe; a duplicated
// path must not be skipped by the in-flight tracker.
TEST_F(LinuxMounts, statfs_duplicate_paths_share_one_probe) {
  std::atomic<int> calls{0};
  auto results = getStatFsInfoWithTimeout(
      {"/dup", "/dup"}, std::chrono::seconds(5), [&calls](const std::string&) {
        ++calls;
        return some();
      });

  ASSERT_EQ(results.size(), 2U);
  EXPECT_TRUE(results[0] != boost::none);
  EXPECT_TRUE(results[1] != boost::none);
  EXPECT_EQ(calls.load(), 1);
}

// A path whose probe is still hung from a prior call is skipped on the next
// call so leaked threads cannot accumulate without bound across queries.
TEST_F(LinuxMounts, statfs_skips_path_already_in_flight) {
  const auto short_timeout = std::chrono::milliseconds(100);

  auto first = getStatFsInfoWithTimeout(
      {"/leak"}, short_timeout, [](const std::string&) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return some();
      });
  ASSERT_EQ(first.size(), 1U);
  EXPECT_TRUE(first[0] == boost::none);

  std::atomic<int> calls{0};
  auto start = std::chrono::steady_clock::now();
  auto second = getStatFsInfoWithTimeout(
      {"/leak"}, std::chrono::seconds(5), [&calls](const std::string&) {
        ++calls;
        return some();
      });
  auto elapsed = std::chrono::steady_clock::now() - start;

  ASSERT_EQ(second.size(), 1U);
  EXPECT_TRUE(second[0] == boost::none);
  EXPECT_EQ(calls.load(), 0);
  EXPECT_LT(elapsed, std::chrono::seconds(1));
}
} // namespace
} // namespace osquery
