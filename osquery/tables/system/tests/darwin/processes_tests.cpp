/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed as defined on the LICENSE file found in the
 *  root directory of this source tree.
 */

#include <CoreServices/CoreServices.h>

#include <gtest/gtest.h>
#include <osquery/rows/processes.h>

#include <osquery/core/sql/query_data.h>
#include <osquery/logger.h>
#include <osquery/tables.h>
#include <osquery/utils/status/status.h>

namespace osquery {
namespace tables {

void genProcUniquePid(QueryContext& context, int pid, ProcessesRow& r);
void genProcArch(QueryContext& context, int pid, ProcessesRow& r);

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
} // namespace tables
} // namespace osquery
