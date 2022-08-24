/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

// Sanity check integration test for processes
// Spec file: specs/processes.table

#include <osquery/tests/integration/tables/helper.h>

#include <osquery/utils/conversions/tryto.h>
#include <osquery/utils/info/platform_type.h>
#include <osquery/utils/system/uptime.h>

namespace osquery {
namespace table_tests {

class ProcessesTest : public testing::Test {
 protected:
  void SetUp() override {
    setUpEnvironment();
  }
};

TEST_F(ProcessesTest, test_sanity) {
  // 1. Query data
  auto const data = execute_query("select * from processes");
  // 2. Check size before validation
  ASSERT_GE(data.size(), 2ul);

  auto const now = std::time(nullptr);
  auto const boot_time = now - getUptime() - 1;

  // The getUptime API does not work how we expect it should on Windows.
  if (!isPlatform(PlatformType::TYPE_WINDOWS)) {
    EXPECT_GE(now, boot_time);
  }

  auto timeSanityCheck = [&now, &boot_time](auto value) {
    auto start_time_exp = tryTo<std::time_t>(value);
    if (start_time_exp.isError()) {
      return false;
    }
    auto const start_time = start_time_exp.take();
    if (start_time == -1) {
      return true;
    }
    return start_time <= now && boot_time <= start_time;
  };

  ValidationMap row_map = {
      {"pid", IntType},
      {"name", NormalType},
      {"path", NormalType},
      {"cmdline", NormalType},
      {"state", NormalType},
      {"cwd", NormalType},
      {"root", NormalType},
      {"uid", IntType},
      {"gid", IntType},
      {"euid", IntType},
      {"egid", IntType},
      {"suid", IntType},
      {"sgid", IntType},
      {"on_disk", IntType},
      {"wired_size", IntType},
      {"resident_size", NormalType},
      {"total_size", NormalType},
      {"user_time", IntType},
      {"system_time", IntType},
      {"disk_bytes_read", NormalType},
      {"disk_bytes_written", NormalType},
      {"parent", IntType},
      {"pgroup", IntType},
      {"threads", IntType},
      {"nice", IntType},
  };

  // The getUptime API does not work how we expect it should on Windows.
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    row_map.emplace("start_time", IntType);
  } else {
    row_map.emplace("start_time", timeSanityCheck);
  }

  // Add the platform-specific columns.
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    row_map.emplace("elevated_token", IntType);
    row_map.emplace("secure_process", IntType);
    row_map.emplace("protection_type", NormalType);
    row_map.emplace("virtual_process", IntType);
    row_map.emplace("elapsed_time", IntType);
    row_map.emplace("handle_count", IntType);
    row_map.emplace("percent_processor_time", IntType);
  }

  if (isPlatform(PlatformType::TYPE_OSX)) {
    row_map.emplace("upid", IntType);
    row_map.emplace("uppid", IntType);
    row_map.emplace("cpu_type", IntType);
    row_map.emplace("cpu_subtype", IntType);
    row_map.emplace("translated", IntType);
  }

  if (isPlatform(PlatformType::TYPE_LINUX)) {
    row_map.emplace("cgroup_path", NormalType);
  }

  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
