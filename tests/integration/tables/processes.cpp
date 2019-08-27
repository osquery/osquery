
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
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

  EXPECT_GE(now, boot_time);

  ValidatatioMap row_map = {
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
      {"start_time",
       [&now, &boot_time](auto value) {
         auto start_time_exp = tryTo<std::time_t>(value);
         if (start_time_exp.isError()) {
           return false;
         }
         auto const start_time = start_time_exp.take();
         if (start_time == -1) {
           return true;
         }
         return start_time <= now && boot_time <= start_time;
       }},

      {"parent", IntType},
      {"pgroup", IntType},
      {"threads", IntType},
      {"nice", IntType},
  };
  if (isPlatform(PlatformType::TYPE_WINDOWS)) {
    row_map.emplace("is_elevated_token", NormalType);
    row_map.emplace("elapsed_time", IntType);
    row_map.emplace("handle_count", IntType);
    row_map.emplace("percent_processor_time", IntType);
  }
  if (isPlatform(PlatformType::TYPE_OSX)) {
    row_map.emplace("upid", IntType);
    row_map.emplace("uppid", IntType);
    row_map.emplace("cpu_type", IntType);
    row_map.emplace("cpu_subtype", IntType);
  }
  validate_rows(data, row_map);
}

} // namespace table_tests
} // namespace osquery
