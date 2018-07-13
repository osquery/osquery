/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <CoreServices/CoreServices.h>

#include <gtest/gtest.h>

#include <osquery/logger.h>

#include "osquery/core/conversions.h"
#include "osquery/tests/test_util.h"

namespace osquery {
namespace tables {

void genProcUniquePid(QueryContext& context, int pid, Row& r);
void genProcArch(QueryContext& context, int pid, Row& r);

class DarwinProcessesTests : public testing::Test {};

TEST_F(DarwinProcessesTests, test_unique_pid) {
  Row r;
  QueryContext ctx;
  ctx.colsUsed = UsedColumns({"upid"});
  genProcUniquePid(ctx, 1, r);
  EXPECT_NE(r["upid"], "-1");
  EXPECT_NE(r["uppid"], "-1");
}

TEST_F(DarwinProcessesTests, test_process_arch) {
  if (getuid() != 0 || getgid() != 0) {
    return;
  }
  Row r;
  QueryContext ctx;
  ctx.colsUsed = UsedColumns({"cpu_type"});
  genProcArch(ctx, 1, r);
  EXPECT_NE(r["cpu_type"], "-1");
  EXPECT_NE(r["cpu_subtype"], "-1");
}
} // namespace tables
} // namespace osquery
