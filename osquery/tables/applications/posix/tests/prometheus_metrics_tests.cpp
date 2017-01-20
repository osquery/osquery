/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */
#include <gtest/gtest.h>

#include <osquery/tables/applications/posix/prometheus_metrics.h>

namespace osquery {
namespace tables {

class TestPM : public PrometheusMetrics {
 public:
  std::map<std::string, retData*> scrapeResults_;
  TestPM(std::vector<std::string> urls) : PrometheusMetrics(urls) {}

 protected:
  virtual std::map<std::string, retData*> scrapeTargets() {
    return scrapeResults_;
  }
};

inline bool comparePMRow(Row& row1, Row& row2) {
  return (row1[col_target_name] + row1[col_metric]) <
         (row2[col_target_name] + row2[col_metric]);
}

void validatePMTest(PrometheusMetrics& pm, QueryData& expected) {
  QueryData got = pm.queryPrometheusTargets();

  ASSERT_EQ(got.size(), expected.size());

  // sort rows
  std::sort(got.begin(), got.end(), comparePMRow);
  std::sort(expected.begin(), expected.end(), comparePMRow);

  for (size_t i = 0; i < got.size(); i++) {
    EXPECT_TRUE(expected[i][col_target_name] == got[i][col_target_name]);
    EXPECT_TRUE(expected[i][col_metric] == got[i][col_metric]);
    EXPECT_TRUE(expected[i][col_value] == got[i][col_value]);
    EXPECT_TRUE(expected[i][col_timestamp] == got[i][col_timestamp]);
  }
}

class PrometheusMetricsTest : public ::testing::Test {};

TEST_F(PrometheusMetricsTest, no_target_urls) {
  std::vector<std::string> urls;
  PrometheusMetrics pm(urls);

  QueryData expected;

  validatePMTest(pm, expected);
}

TEST_F(PrometheusMetricsTest, happy_path_0_metrics) {
  /* Initialize stubbed scrape results.
   Must allocate on heap b/c queryPrometheusTargets assumes so and calls
  delete. */
  std::chrono::milliseconds now(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()));

  retData* r0 = new retData{0, "", now};
  std::map<std::string, retData*> sr = {{"example1.com", r0}};

  // Initialize expected output.
  QueryData expected;

  // Construct url vector for obj instantiation.
  std::vector<std::string> urls;
  for (const auto& ea : sr) {
    urls.push_back(ea.first);
  }

  // Initialize TestPM instance
  TestPM pm(urls);
  pm.scrapeResults_ = sr;

  validatePMTest(pm, expected);
}

TEST_F(PrometheusMetricsTest, happy_path_1_metric) {
  /* Initialize stubbed scrape results.
   Must allocate on heap b/c queryPrometheusTargets assumes so and calls
  delete. */
  std::chrono::milliseconds now(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()));
  retData* r0 = new retData{
      500, "# some comment\nprocess_virtual_memory_bytes 1.3934592e+07", now};
  std::map<std::string, retData*> sr = {{"example1.com", r0}};

  // Initialize expected output.
  QueryData expected = {
      {{col_target_name, "example1.com"},
       {col_metric, "process_virtual_memory_bytes"},
       {col_value, "1.3934592e+07"},
       {col_timestamp, std::to_string(now.count())}},
  };

  // Construct url vector for obj instantiation.
  std::vector<std::string> urls;
  for (const auto& ea : sr) {
    urls.push_back(ea.first);
  }

  // Initialize TestPM instance
  TestPM pm(urls);
  pm.scrapeResults_ = sr;

  validatePMTest(pm, expected);
}

TEST_F(PrometheusMetricsTest, happy_path_10_metrics_1_target) {
  /* Initialize stubbed scrape results.
   Must allocate on heap b/c queryPrometheusTargets assumes so and calls
  delete. */
  std::chrono::milliseconds now(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()));
  std::string nowStr(std::to_string(now.count()));

  retData* r0 = new retData{
      500,
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
  std::map<std::string, retData*> sr = {{"example1.com", r0}};

  // Initialize expected output.
  QueryData expected = {
      {
          {col_target_name, "example1.com"},
          {col_metric, "node_vmstat_unevictable_pgs_stranded"},
          {col_value, "0"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "node_vmstat_workingset_activate"},
          {col_value, "0"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "node_vmstat_workingset_nodereclaim"},
          {col_value, "0"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "node_vmstat_workingset_refault"},
          {col_value, "0"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "process_cpu_seconds_total"},
          {col_value, "0.25"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "process_max_fds"},
          {col_value, "1.048576e+06"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "process_open_fds"},
          {col_value, "7"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "process_resident_memory_bytes"},
          {col_value, "1.0170368e+07"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "process_start_time_seconds"},
          {col_value, "1.48475733855e+09"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "process_virtual_memory_bytes"},
          {col_value, "1.3934592e+07"},
          {col_timestamp, nowStr},
      },
  };

  // Construct url vector for obj instantiation.
  std::vector<std::string> urls;
  for (const auto& ea : sr) {
    urls.push_back(ea.first);
  }

  // Initialize TestPM instance
  TestPM pm(urls);
  pm.scrapeResults_ = sr;

  validatePMTest(pm, expected);
}

TEST_F(PrometheusMetricsTest, happy_path_10_metrics_2_targets) {
  /* Initialize stubbed scrape results.
   Must allocate on heap b/c queryPrometheusTargets assumes so and calls
  delete. */
  std::chrono::milliseconds now(
      std::chrono::duration_cast<std::chrono::milliseconds>(
          std::chrono::system_clock::now().time_since_epoch()));

  std::string nowStr(std::to_string(now.count()));

  retData* r0 = new retData{
      500,
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
  retData* r1 = new retData{
      500,
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
  std::map<std::string, retData*> sr = {{"example1.com", r0},
                                        {"example2.com", r1}};

  // Initialize expected output.
  QueryData expected = {
      {
          {col_target_name, "example1.com"},
          {col_metric, "node_vmstat_unevictable_pgs_stranded"},
          {col_value, "0"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "node_vmstat_workingset_activate"},
          {col_value, "0"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "node_vmstat_workingset_nodereclaim"},
          {col_value, "0"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "node_vmstat_workingset_refault"},
          {col_value, "0"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "process_cpu_seconds_total"},
          {col_value, "0.25"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "process_max_fds"},
          {col_value, "1.048576e+06"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "process_open_fds"},
          {col_value, "7"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "process_resident_memory_bytes"},
          {col_value, "1.0170368e+07"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "process_start_time_seconds"},
          {col_value, "1.48475733855e+09"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example1.com"},
          {col_metric, "process_virtual_memory_bytes"},
          {col_value, "1.3934592e+07"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example2.com"},
          {col_metric, "node_vmstat_unevictable_pgs_stranded2"},
          {col_value, "0"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example2.com"},
          {col_metric, "node_vmstat_workingset_activate2"},
          {col_value, "0"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example2.com"},
          {col_metric, "node_vmstat_workingset_nodereclaim2"},
          {col_value, "0"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example2.com"},
          {col_metric, "node_vmstat_workingset_refault2"},
          {col_value, "0"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example2.com"},
          {col_metric, "process_cpu_seconds_total2"},
          {col_value, "0.25"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example2.com"},
          {col_metric, "process_max_fds2"},
          {col_value, "1.048576e+06"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example2.com"},
          {col_metric, "process_open_fds2"},
          {col_value, "7"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example2.com"},
          {col_metric, "process_resident_memory_bytes2"},
          {col_value, "1.0170368e+07"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example2.com"},
          {col_metric, "process_start_time_seconds2"},
          {col_value, "1.48475733855e+09"},
          {col_timestamp, nowStr},
      },
      {
          {col_target_name, "example2.com"},
          {col_metric, "process_virtual_memory_bytes2"},
          {col_value, "1.3934592e+07"},
          {col_timestamp, nowStr},
      },
  };

  // Construct url vector for obj instantiation.
  std::vector<std::string> urls;
  for (const auto& ea : sr) {
    urls.push_back(ea.first);
  }

  // Initialize TestPM instance
  TestPM pm(urls);
  pm.scrapeResults_ = sr;

  validatePMTest(pm, expected);
}
}
}
