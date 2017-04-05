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

#include <osquery/sql.h>

#include "osquery/tests/test_util.h"

namespace osquery {
namespace tables {

class StartupTablesTest : public testing::Test {};

TEST_F(StartupTablesTest, test_startup_table) {
  SQL results("SELECT * FROM startup");
  EXPECT_TRUE(results.ok());
}
}
}
