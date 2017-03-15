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

#include <osquery/tables/system/windows/registry.h>

#include "osquery/tests/test_util.h"

namespace osquery {
namespace tables {

class RegistryTablesTest : public testing::Test {};

TEST_F(RegistryTablesTest, test_registry_existing_key) {
  QueryData results;
  auto key = "HKEY_LOCAL_MACHINE\\SOFTWARE";
  queryKey(key, results);
  EXPECT_TRUE(results.size() > 0);
}

TEST_F(RegistryTablesTest, test_registry_non_existing_key) {
  QueryData results;
  auto key = "HKEY_LOCAL_MACHINE\\PATH\\to\\madeup\\key";
  queryKey(key, results);
  EXPECT_TRUE(results.size() == 0);
}
}
}
