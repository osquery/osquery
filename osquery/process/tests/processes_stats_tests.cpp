/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/process/processes_stats.h>

namespace osquery {
class ProcessesStatsTests : public testing::Test {};

TEST_F(ProcessesStatsTests, test_adding_and_retrieving_process_stats) {
  ProcessesStats processes_stats;
  const auto start_cpu_time = 100;
  const auto update_interval = 2;
  const auto start_process_time = 0;

  processes_stats.updateProcessStats(
      123, start_cpu_time, start_process_time, update_interval);

  auto opt_process_stats = processes_stats.getProcessStats(123);
  ASSERT_TRUE(opt_process_stats.has_value());

  // At the first sample, the cpu usage is 0
  EXPECT_EQ(opt_process_stats->cpu_usage, 0);

  const auto new_cpu_time = 1000;
  processes_stats.updateProcessStats(
      123, new_cpu_time, start_process_time, update_interval);

  opt_process_stats = processes_stats.getProcessStats(123);
  ASSERT_TRUE(opt_process_stats.has_value());

  auto expected_cpu_usage =
      ((new_cpu_time - start_cpu_time) * 100ULL) / (update_interval * 1000ULL);

  EXPECT_EQ(opt_process_stats->cpu_usage, expected_cpu_usage);
}

TEST_F(ProcessesStatsTests, test_retrieving_nonexisting_process_stats) {
  ProcessesStats processes_stats;
  auto opt_process_stats = processes_stats.getProcessStats(101);

  ASSERT_FALSE(opt_process_stats.has_value());
}

TEST_F(ProcessesStatsTests, test_reappearing_pid) {
  ProcessesStats processes_stats;
  // The process stats now have a generation of 0. The current generation is 0
  processes_stats.updateProcessStats(123, 1000, 0, 2);

  processes_stats.increaseGeneration();

  // We see the process again, we can internally calculate a cpu usage now
  processes_stats.updateProcessStats(123, 1500, 0, 2);

  auto opt_process_stats = processes_stats.getProcessStats(123);
  ASSERT_TRUE(opt_process_stats.has_value());

  ASSERT_EQ(opt_process_stats->cpu_usage, 25);
  ASSERT_EQ(opt_process_stats->cpu_peak_usage, 25);

  // We don't update the process stats, as if the process 123 disappeared
  processes_stats.increaseGeneration();

  /* The pid 123 has reappeared, it's clearly a new process.
     Although the processes stats "database" already contains this pid
     stats, the CPU time has gone back instead of staying the same or
     increasing, so the stats they will be reset
     as if it's the first time we see it. */
  processes_stats.increaseGeneration();
  processes_stats.updateProcessStats(123, 800, 0, 2);

  opt_process_stats = processes_stats.getProcessStats(123);
  ASSERT_TRUE(opt_process_stats.has_value());
  EXPECT_EQ(opt_process_stats->cpu_usage, 0);

  // We now test processes with different start time but same pid
  processes_stats.updateProcessStats(456, 100, 100, 2);
  processes_stats.increaseGeneration();

  // We see the same process again, with increased cpu time. We have a cpu usage
  processes_stats.updateProcessStats(456, 1100, 100, 2);

  opt_process_stats = processes_stats.getProcessStats(456);
  ASSERT_TRUE(opt_process_stats.has_value());

  ASSERT_EQ(opt_process_stats->cpu_usage, 50);
  ASSERT_EQ(opt_process_stats->cpu_peak_usage, 50);

  /* The process has disappeared, we don't know it yet,
     since there hasn't been another sample,
     but the process start time changed, while the cpu time is the same.
     Given the different start time, the existing stats should be reset. */
  processes_stats.increaseGeneration();
  processes_stats.updateProcessStats(456, 1100, 1200, 2);

  opt_process_stats = processes_stats.getProcessStats(456);
  ASSERT_TRUE(opt_process_stats.has_value());

  ASSERT_EQ(opt_process_stats->cpu_usage, 0);
  ASSERT_EQ(opt_process_stats->cpu_peak_usage, 0);
}

TEST_F(ProcessesStatsTests, test_processes_stats_cleanup) {
  ProcessesStats processes_stats;
  // The process stats now have a generation of 0. The current generation is 0
  processes_stats.updateProcessStats(123, 1000, 0, 2);

  // The process is still present, it should not have been removed
  processes_stats.cleanupProcessStats();
  auto opt_process_stats = processes_stats.getProcessStats(123);
  ASSERT_TRUE(opt_process_stats.has_value());

  /* The current generation is 1. We don't update the process stats,
     as if the process 123 disappeared */
  processes_stats.increaseGeneration();

  // Add a new process. Generation is 1
  processes_stats.updateProcessStats(124, 100, 0, 2);

  // Now the pid 123 should be removed, since it wasn't updated anymore
  processes_stats.cleanupProcessStats();
  opt_process_stats = processes_stats.getProcessStats(123);
  ASSERT_FALSE(opt_process_stats.has_value());

  // While pid 124 is still present
  opt_process_stats = processes_stats.getProcessStats(124);
  ASSERT_TRUE(opt_process_stats.has_value());
}

TEST_F(ProcessesStatsTests, test_pid_reuse) {
  ProcessesStats processes_stats;
  // The process stats now have a generation of 0. The current generation is 0
  processes_stats.updateProcessStats(123, 1000, 0, 2);

  // The current generation is 1
  processes_stats.increaseGeneration();

  /* The process stats now have a generation of 1.
     The cpu usage is now calculated */
  processes_stats.updateProcessStats(123, 1500, 0, 2);

  auto opt_process_stats = processes_stats.getProcessStats(123);
  ASSERT_TRUE(opt_process_stats.has_value());
  EXPECT_EQ(opt_process_stats->cpu_usage, 25);

  // The current generation is 2
  processes_stats.increaseGeneration();

  /* Now we simulate a pid reuse, where the new process
     will have a lower cpu time */
  processes_stats.updateProcessStats(123, 100, 0, 2);

  /* We should detect the pid reuse (or lower cpu time case)
     and treat this as a new sample resetting the stats */
  opt_process_stats = processes_stats.getProcessStats(123);
  ASSERT_TRUE(opt_process_stats.has_value());
  EXPECT_EQ(opt_process_stats->cpu_usage, 0);
}

TEST_F(ProcessesStatsTests, test_cpu_peak_usage) {
  ProcessesStats processes_stats;
  processes_stats.updateProcessStats(123, 1000, 0, 2);
  processes_stats.updateProcessStats(123, 1500, 0, 2);

  // First cpu usage sample created, should be 25%, same for the peak
  auto opt_process_stats = processes_stats.getProcessStats(123);
  ASSERT_TRUE(opt_process_stats.has_value());
  EXPECT_EQ(opt_process_stats->cpu_usage, 25);
  EXPECT_EQ(opt_process_stats->cpu_peak_usage, 25);

  int new_time = 1500;

  // Add another 29 samples, by default 30 is the number of samples kept
  for (int i = 0; i < 29; ++i) {
    new_time = 1500 + ((i + 1) * 200);
    processes_stats.updateProcessStats(123, new_time, 0, 2);
    // The peak should not change
    opt_process_stats = processes_stats.getProcessStats(123);
    ASSERT_TRUE(opt_process_stats.has_value());
    EXPECT_EQ(opt_process_stats->cpu_usage, 10);
    EXPECT_EQ(opt_process_stats->cpu_peak_usage, 25);
  }

  /* Now the oldest sample, 25%, should've been overwritten.
     The peak should now be 10%, which is one of the samples we've added in
     the previous loop, which is higher than the sample we are adding here
     which is 5% */
  new_time += 100;
  processes_stats.updateProcessStats(123, new_time, 0, 2);
  opt_process_stats = processes_stats.getProcessStats(123);
  ASSERT_TRUE(opt_process_stats.has_value());
  EXPECT_EQ(opt_process_stats->cpu_usage, 5);
  EXPECT_EQ(opt_process_stats->cpu_peak_usage, 10);

  // We finally add a new peak, which should be 50%
  processes_stats.updateProcessStats(123, new_time + 1000, 0, 2);
  opt_process_stats = processes_stats.getProcessStats(123);
  ASSERT_TRUE(opt_process_stats.has_value());
  EXPECT_EQ(opt_process_stats->cpu_usage, 50);
  EXPECT_EQ(opt_process_stats->cpu_peak_usage, 50);
}

}; // namespace osquery
