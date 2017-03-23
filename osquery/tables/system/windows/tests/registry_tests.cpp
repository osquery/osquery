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

TEST_F(RegistryTablesTest, test_explode_registry_path_normal) {
  auto path = "HKEY_LOCAL_MACHINE\\PATH\\to\\madeup\\key";
  std::string rKey;
  std::string rHive;

  explodeRegistryPath(path, rHive, rKey);
  EXPECT_TRUE(rKey == "PATH\\to\\madeup\\key");
  EXPECT_TRUE(rHive == "HKEY_LOCAL_MACHINE");

  path = "HKEY_LOCAL_MACHINE\\PATH\\to\\madeup\\key\\";
  explodeRegistryPath(path, rHive, rKey);
  EXPECT_TRUE(rKey == "PATH\\to\\madeup\\key");
  EXPECT_TRUE(rHive == "HKEY_LOCAL_MACHINE");
}

TEST_F(RegistryTablesTest, test_explode_registry_path_just_hive) {
  auto path = "HKEY_LOCAL_MACHINE";
  std::string rKey;
  std::string rHive;

  explodeRegistryPath(path, rHive, rKey);
  EXPECT_TRUE(rKey == "");
  EXPECT_TRUE(rHive == "HKEY_LOCAL_MACHINE");

  path = "HKEY_LOCAL_MACHINE\\";
  explodeRegistryPath(path, rHive, rKey);
  EXPECT_TRUE(rKey == "");
  EXPECT_TRUE(rHive == "HKEY_LOCAL_MACHINE");
}

TEST_F(RegistryTablesTest, test_sanitize_registry_strings) {
  BYTE dataBuff[] = "This is a test";
  DWORD dataType = REG_SZ;
  const DWORD dataSize = sizeof(dataBuff) / sizeof(dataBuff[0]);
  Status status;

  for (const auto& type : kRegistryStringTypes) {
    status = sanitizeRegistryStrings(type, dataBuff, dataSize);
    EXPECT_TRUE(status.ok());
    EXPECT_TRUE(dataBuff[dataSize - 1] == 0x00);

    dataBuff[dataSize - 1] = 'x';
    status = sanitizeRegistryStrings(type, dataBuff, dataSize);
    EXPECT_TRUE(status.ok());
    EXPECT_TRUE(dataBuff[dataSize - 1] == 0x00);

  }

  dataBuff[dataSize - 1] = 'x';
  status = sanitizeRegistryStrings(REG_BINARY, dataBuff, dataSize);
  EXPECT_TRUE(status.ok());
  EXPECT_FALSE(dataBuff[dataSize - 1] == 0x00);

  status = sanitizeRegistryStrings(dataType, NULL, dataSize);
  EXPECT_FALSE(status.ok());

}
}
}
