/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <CoreServices/CoreServices.h>

#include <gtest/gtest.h>
#include <osquery/rows/processes.h>

#include <osquery/core/sql/query_data.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/status/status.h>

namespace osquery {
namespace tables {

void genProcUniquePid(QueryContext& context, int pid, ProcessesRow& r);
void genProcArch(QueryContext& context, int pid, ProcessesRow& r);
bool parseProcCmdline(std::string& args, size_t len);

class DarwinProcessesTests : public testing::Test {};

TEST_F(DarwinProcessesTests, test_unique_pid) {
  ProcessesRow r;
  QueryContext ctx;
  ctx.colsUsed = UsedColumns({"upid"});
  ctx.colsUsedBitset = ProcessesRow::UPID;
  genProcUniquePid(ctx, 1, r);
  EXPECT_NE(r.upid_col, -1);
  EXPECT_NE(r.uppid_col, -1);
}

TEST_F(DarwinProcessesTests, test_cmdline_parsing) {
  int argc = 2;
  std::string cmdline("0000/bin/sh0/bin/sh0-c0PATH=/");
  std::replace(cmdline.begin(), cmdline.end(), '0', '\0');
  memcpy(&cmdline[0], &argc, sizeof(argc));
  EXPECT_TRUE(parseProcCmdline(cmdline, cmdline.size()));
  EXPECT_EQ("/bin/sh -c", cmdline);

  cmdline = "0000";
  std::replace(cmdline.begin(), cmdline.end(), '0', '\0');
  memcpy(&cmdline[0], &argc, sizeof(argc));
  EXPECT_FALSE(parseProcCmdline(cmdline, cmdline.size()));

  cmdline = "0000/bin/sh";
  std::replace(cmdline.begin(), cmdline.end(), '0', '\0');
  memcpy(&cmdline[0], &argc, sizeof(argc));
  EXPECT_FALSE(parseProcCmdline(cmdline, cmdline.size()));
}

TEST_F(DarwinProcessesTests, test_process_arch) {
  if (getuid() != 0 || getgid() != 0) {
    return;
  }
  ProcessesRow r;
  QueryContext ctx;
  ctx.colsUsed = UsedColumns({"cpu_type"});
  ctx.colsUsedBitset = ProcessesRow::CPU_TYPE;
  genProcArch(ctx, 1, r);
  EXPECT_NE(r.cpu_type_col, -1);
  EXPECT_NE(r.cpu_subtype_col, -1);
}

TEST_F(DarwinProcessesTests, test_column_overflow) {
  ProcessesRow r;
  QueryContext ctx;
  ctx.colsUsed = UsedColumns({"cpu_subtype"});
  ctx.colsUsedBitset = ProcessesRow::CPU_SUBTYPE;
  for (unsigned i = 0; i < 64; i++) {
    const unsigned long long current_mask = 1ULL << i;
    if (current_mask !=
        static_cast<decltype(current_mask)>(ProcessesRow::CPU_SUBTYPE)) {
      EXPECT_FALSE(ctx.isAnyColumnUsed(current_mask))
          << "Processes table is not queried for the " + std::to_string(i) +
                 "th column.";
    } else {
      EXPECT_TRUE(ctx.isAnyColumnUsed(current_mask))
          << "Processes table is queried for the " + std::to_string(i) +
                 "th column, but does not say so.";
    }
  }
}
} // namespace tables
} // namespace osquery
