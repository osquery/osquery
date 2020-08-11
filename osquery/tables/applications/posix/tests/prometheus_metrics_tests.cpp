/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <osquery/tables/applications/posix/prometheus_metrics.h>

namespace osquery {
namespace tables {

inline bool comparePMRow(Row& row1, Row& row2) {
  return (row1[kColTargetName] + row1[kColMetric]) <
         (row2[kColTargetName] + row2[kColMetric]);
}

void validate(std::map<std::string, PrometheusResponseData>& scrapeResults,
              QueryData& expected) {
  QueryData got;
  parseScrapeResults(scrapeResults, got);

  ASSERT_EQ(got.size(), expected.size());

  // sort rows
  std::sort(got.begin(), got.end(), comparePMRow);
  std::sort(expected.begin(), expected.end(), comparePMRow);

  for (size_t i = 0; i < got.size(); i++) {
    EXPECT_TRUE(expected[i][kColTargetName] == got[i][kColTargetName]);
    EXPECT_TRUE(expected[i][kColMetric] == got[i][kColMetric]);
    EXPECT_TRUE(expected[i][kColValue] == got[i][kColValue]);
    EXPECT_TRUE(expected[i][kColTimeStamp] == got[i][kColTimeStamp]);
  }
}

class PrometheusMetricsTest : public ::testing::Test {};

TEST_F(PrometheusMetricsTest, no_targets) {
  std::map<std::string, PrometheusResponseData> sr;

  QueryData expected;

  validate(sr, expected);
}

TEST_F(PrometheusMetricsTest, happy_path_0_metrics) {
  // Initialize stubbed scrape results.
  std::chrono::milliseconds now(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()));

  PrometheusResponseData r0 = PrometheusResponseData{"", now};
  std::map<std::string, PrometheusResponseData> sr = {{"example1.com", r0}};

  // Initialize expected output.
  QueryData expected;

  validate(sr, expected);
}

TEST_F(PrometheusMetricsTest, happy_path_1_metric) {
  // Initialize stubbed scrape results.
  std::chrono::milliseconds now(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()));
  PrometheusResponseData r0 = PrometheusResponseData{
      "# some comment\nprocess_virtual_memory_bytes 1.3934592e+07", now};
  std::map<std::string, PrometheusResponseData> sr = {{"example1.com", r0}};

  // Initialize expected output.
  QueryData expected = {
      {{kColTargetName, "example1.com"},
       {kColMetric, "process_virtual_memory_bytes"},
       {kColValue, "1.3934592e+07"},
       {kColTimeStamp, std::to_string(now.count())}},
  };

  validate(sr, expected);
}

TEST_F(PrometheusMetricsTest, happy_path_extra_spaces_lines) {
  // Initialize stubbed scrape results.
  std::chrono::milliseconds now(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()));
  PrometheusResponseData r0 = PrometheusResponseData{
      "# some comment\n\nprocess_virtual_memory_bytes   1.3934592e+07  ", now};
  std::map<std::string, PrometheusResponseData> sr = {{"example1.com", r0}};

  // Initialize expected output.
  QueryData expected = {
      {{kColTargetName, "example1.com"},
       {kColMetric, "process_virtual_memory_bytes"},
       {kColValue, "1.3934592e+07"},
       {kColTimeStamp, std::to_string(now.count())}},
  };

  validate(sr, expected);
}

TEST_F(PrometheusMetricsTest, happy_path_10_metrics_1_target) {
  // Initialize stubbed scrape results.
  std::chrono::milliseconds now(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()));
  std::string nowStr(std::to_string(now.count()));

  PrometheusResponseData r0 = PrometheusResponseData{
      "# HELP node_vmstat_unevictable_pgs_stranded /proc/vmstat information "
      "field unevictable_pgs_stranded.\n# TYPE "
      "node_vmstat_unevictable_pgs_stranded "
      "untyped\nnode_vmstat_unevictable_pgs_stranded 0\n# HELP "
      "node_vmstat_workingset_activate /proc/vmstat information field "
      "workingset_activate.\n# TYPE node_vmstat_workingset_activate "
      "untyped\nnode_vmstat_workingset_activate 0\n# HELP "
      "node_vmstat_workingset_nodereclaim /proc/vmstat information field "
      "workingset_nodereclaim.\n# TYPE node_vmstat_workingset_nodereclaim "
      "untyped\nnode_vmstat_workingset_nodereclaim 0\n# HELP "
      "node_vmstat_workingset_refault /proc/vmstat information field "
      "workingset_refault.\n# TYPE node_vmstat_workingset_refault "
      "untyped\nnode_vmstat_workingset_refault 0\n# HELP "
      "process_cpu_seconds_total Total user and system CPU time spent in "
      "seconds.\n# TYPE process_cpu_seconds_total "
      "counter\nprocess_cpu_seconds_total 0.25\n# HELP process_max_fds Maximum "
      "number of open file descriptors.\n# TYPE process_max_fds "
      "gauge\nprocess_max_fds 1.048576e+06\n# HELP process_open_fds Number of "
      "open file descriptors.\n# TYPE process_open_fds gauge\nprocess_open_fds "
      "7\n# HELP process_resident_memory_bytes Resident memory size in "
      "bytes.\n# TYPE process_resident_memory_bytes "
      "gauge\nprocess_resident_memory_bytes 1.0170368e+07\n# HELP "
      "process_start_time_seconds Start time of the process since unix epoch "
      "in seconds.\n# TYPE process_start_time_seconds "
      "gauge\nprocess_start_time_seconds 1.48475733855e+09\n# HELP "
      "process_virtual_memory_bytes Virtual memory size in bytes.\n# TYPE "
      "process_virtual_memory_bytes gauge\nprocess_virtual_memory_bytes "
      "1.3934592e+07\n",
      now,
  };
  std::map<std::string, PrometheusResponseData> sr = {{"example1.com", r0}};

  // Initialize expected output.
  QueryData expected = {
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "node_vmstat_unevictable_pgs_stranded"},
          {kColValue, "0"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "node_vmstat_workingset_activate"},
          {kColValue, "0"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "node_vmstat_workingset_nodereclaim"},
          {kColValue, "0"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "node_vmstat_workingset_refault"},
          {kColValue, "0"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "process_cpu_seconds_total"},
          {kColValue, "0.25"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "process_max_fds"},
          {kColValue, "1.048576e+06"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "process_open_fds"},
          {kColValue, "7"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "process_resident_memory_bytes"},
          {kColValue, "1.0170368e+07"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "process_start_time_seconds"},
          {kColValue, "1.48475733855e+09"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "process_virtual_memory_bytes"},
          {kColValue, "1.3934592e+07"},
          {kColTimeStamp, nowStr},
      },
  };

  validate(sr, expected);
}

TEST_F(PrometheusMetricsTest, happy_path_10_metrics_2_targets) {
  // Initialize stubbed scrape results.
  std::chrono::milliseconds now(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()));

  std::string nowStr(std::to_string(now.count()));

  PrometheusResponseData r0 = PrometheusResponseData{
      "# HELP node_vmstat_unevictable_pgs_stranded /proc/vmstat information "
      "field unevictable_pgs_stranded.\n# TYPE "
      "node_vmstat_unevictable_pgs_stranded "
      "untyped\nnode_vmstat_unevictable_pgs_stranded 0\n# HELP "
      "node_vmstat_workingset_activate /proc/vmstat information field "
      "workingset_activate.\n# TYPE node_vmstat_workingset_activate "
      "untyped\nnode_vmstat_workingset_activate 0\n# HELP "
      "node_vmstat_workingset_nodereclaim /proc/vmstat information field "
      "workingset_nodereclaim.\n# TYPE node_vmstat_workingset_nodereclaim "
      "untyped\nnode_vmstat_workingset_nodereclaim 0\n# HELP "
      "node_vmstat_workingset_refault /proc/vmstat information field "
      "workingset_refault.\n# TYPE node_vmstat_workingset_refault "
      "untyped\nnode_vmstat_workingset_refault 0\n# HELP "
      "process_cpu_seconds_total Total user and system CPU time spent in "
      "seconds.\n# TYPE process_cpu_seconds_total "
      "counter\nprocess_cpu_seconds_total 0.25\n# HELP process_max_fds Maximum "
      "number of open file descriptors.\n# TYPE process_max_fds "
      "gauge\nprocess_max_fds 1.048576e+06\n# HELP process_open_fds Number of "
      "open file descriptors.\n# TYPE process_open_fds gauge\nprocess_open_fds "
      "7\n# HELP process_resident_memory_bytes Resident memory size in "
      "bytes.\n# TYPE process_resident_memory_bytes "
      "gauge\nprocess_resident_memory_bytes 1.0170368e+07\n# HELP "
      "process_start_time_seconds Start time of the process since unix epoch "
      "in seconds.\n# TYPE process_start_time_seconds "
      "gauge\nprocess_start_time_seconds 1.48475733855e+09\n# HELP "
      "process_virtual_memory_bytes Virtual memory size in bytes.\n# TYPE "
      "process_virtual_memory_bytes gauge\nprocess_virtual_memory_bytes "
      "1.3934592e+07\n",
      now,
  };
  PrometheusResponseData r1 = PrometheusResponseData{
      "# HELP node_vmstat_unevictable_pgs_stranded /proc/vmstat information "
      "field unevictable_pgs_stranded.\n# TYPE "
      "node_vmstat_unevictable_pgs_stranded "
      "untyped\nnode_vmstat_unevictable_pgs_stranded2 0\n# HELP "
      "node_vmstat_workingset_activate /proc/vmstat information field "
      "workingset_activate.\n# TYPE node_vmstat_workingset_activate "
      "untyped\nnode_vmstat_workingset_activate2 0\n# HELP "
      "node_vmstat_workingset_nodereclaim /proc/vmstat information field "
      "workingset_nodereclaim.\n# TYPE node_vmstat_workingset_nodereclaim "
      "untyped\nnode_vmstat_workingset_nodereclaim2 0\n# HELP "
      "node_vmstat_workingset_refault /proc/vmstat information field "
      "workingset_refault.\n# TYPE node_vmstat_workingset_refault "
      "untyped\nnode_vmstat_workingset_refault2 0\n# HELP "
      "process_cpu_seconds_total Total user and system CPU time spent in "
      "seconds.\n# TYPE process_cpu_seconds_total "
      "counter\nprocess_cpu_seconds_total2 0.25\n# HELP process_max_fds "
      "Maximum "
      "number of open file descriptors.\n# TYPE process_max_fds "
      "gauge\nprocess_max_fds2 1.048576e+06\n# HELP process_open_fds Number of "
      "open file descriptors.\n# TYPE process_open_fds "
      "gauge\nprocess_open_fds2 "
      "7\n# HELP process_resident_memory_bytes Resident memory size in "
      "bytes.\n# TYPE process_resident_memory_bytes "
      "gauge\nprocess_resident_memory_bytes2 1.0170368e+07\n# HELP "
      "process_start_time_seconds Start time of the process since unix epoch "
      "in seconds.\n# TYPE process_start_time_seconds "
      "gauge\nprocess_start_time_seconds2 1.48475733855e+09\n# HELP "
      "process_virtual_memory_bytes Virtual memory size in bytes.\n# TYPE "
      "process_virtual_memory_bytes gauge\nprocess_virtual_memory_bytes2 "
      "1.3934592e+07\n",
      now,
  };
  std::map<std::string, PrometheusResponseData> sr = {{"example1.com", r0},
                                                      {"example2.com", r1}};

  // Initialize expected output.
  QueryData expected = {
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "node_vmstat_unevictable_pgs_stranded"},
          {kColValue, "0"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "node_vmstat_workingset_activate"},
          {kColValue, "0"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "node_vmstat_workingset_nodereclaim"},
          {kColValue, "0"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "node_vmstat_workingset_refault"},
          {kColValue, "0"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "process_cpu_seconds_total"},
          {kColValue, "0.25"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "process_max_fds"},
          {kColValue, "1.048576e+06"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "process_open_fds"},
          {kColValue, "7"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "process_resident_memory_bytes"},
          {kColValue, "1.0170368e+07"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "process_start_time_seconds"},
          {kColValue, "1.48475733855e+09"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example1.com"},
          {kColMetric, "process_virtual_memory_bytes"},
          {kColValue, "1.3934592e+07"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example2.com"},
          {kColMetric, "node_vmstat_unevictable_pgs_stranded2"},
          {kColValue, "0"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example2.com"},
          {kColMetric, "node_vmstat_workingset_activate2"},
          {kColValue, "0"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example2.com"},
          {kColMetric, "node_vmstat_workingset_nodereclaim2"},
          {kColValue, "0"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example2.com"},
          {kColMetric, "node_vmstat_workingset_refault2"},
          {kColValue, "0"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example2.com"},
          {kColMetric, "process_cpu_seconds_total2"},
          {kColValue, "0.25"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example2.com"},
          {kColMetric, "process_max_fds2"},
          {kColValue, "1.048576e+06"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example2.com"},
          {kColMetric, "process_open_fds2"},
          {kColValue, "7"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example2.com"},
          {kColMetric, "process_resident_memory_bytes2"},
          {kColValue, "1.0170368e+07"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example2.com"},
          {kColMetric, "process_start_time_seconds2"},
          {kColValue, "1.48475733855e+09"},
          {kColTimeStamp, nowStr},
      },
      {
          {kColTargetName, "example2.com"},
          {kColMetric, "process_virtual_memory_bytes2"},
          {kColValue, "1.3934592e+07"},
          {kColTimeStamp, nowStr},
      },
  };

  validate(sr, expected);
}
} // namespace tables
} // namespace osquery
