/*
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/algorithm/string/predicate.hpp>
#include <gtest/gtest.h>

#include <osquery/sql.h>
#include <osquery/tables/system/windows/registry.h>

#include "osquery/tests/test_util.h"

namespace osquery {
namespace tables {

class RegistryTablesTest : public testing::Test {};

const std::string kTestKey = "HKEY_LOCAL_MACHINE\\SOFTWARE";
const std::string kTestSpecificKey =
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Control "
    "Panel";
const std::string kInvalidTestKey = "HKEY_LOCAL_MACHINE\\PATH\\to\\madeup\\key";

TEST_F(RegistryTablesTest, test_registry_existing_key) {
  QueryData results;
  queryKey(kTestKey, results);
  EXPECT_TRUE(results.size() > 0);
}

TEST_F(RegistryTablesTest, test_registry_non_existing_key) {
  QueryData results;
  queryKey(kInvalidTestKey, results);
  EXPECT_TRUE(results.size() == 0);
}

TEST_F(RegistryTablesTest, test_explode_registry_path_normal) {
  auto path = "HKEY_LOCAL_MACHINE\\PATH\\to\\madeup\\key";
  std::string rKey;
  std::string rHive;

  explodeRegistryPath(kInvalidTestKey, rHive, rKey);
  EXPECT_TRUE(rKey == "PATH\\to\\madeup\\key");
  EXPECT_TRUE(rHive == "HKEY_LOCAL_MACHINE");
}

TEST_F(RegistryTablesTest, test_registry_or_clause) {
  SQL results("SELECT * FROM registry WHERE key = \"" + kTestKey +
              "\" OR key = \"" + kTestSpecificKey + "\"");
  auto testKeyFound = false;
  auto specificKeyFound = false;
  EXPECT_TRUE(results.rows().size() > 0);
  for (const auto& row : results.rows()) {
    auto key = row.at("key");
    if (boost::starts_with(key, kTestSpecificKey)) {
      specificKeyFound = true;
    } else if (boost::starts_with(key, kTestKey)) {
      testKeyFound = true;
    } else {
      assert(false);
    }
  }
  EXPECT_TRUE(testKeyFound);
  EXPECT_TRUE(specificKeyFound);
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

TEST_F(RegistryTablesTest, test_basic_registry_globbing) {
  auto testKey = kTestKey + "\\Micro%\\%";
  SQL results("select * from registry where key like \"" + testKey + "\"");
  EXPECT_TRUE(results.rows().size() > 1);
  std::for_each(
      results.rows().begin(), results.rows().end(), [&](const auto& row) {
        auto key = row.at("key");
        EXPECT_TRUE(boost::starts_with(key, kTestKey + "\\Micro"));
        EXPECT_TRUE(std::count(key.begin(), key.end(), '\\') == 3);
      });
}

TEST_F(RegistryTablesTest, test_recursive_registry_globbing) {
  auto testKey = kTestSpecificKey + "\\%%";
  SQL results("select * from registry where key like \"" + testKey + "\"");
  EXPECT_TRUE(results.rows().size() > 1);
  std::for_each(
      results.rows().begin(), results.rows().end(), [&](const auto& row) {
        auto key = row.at("key");
        EXPECT_TRUE(boost::starts_with(key, kTestSpecificKey));
        EXPECT_TRUE(std::count(key.begin(), key.end(), '\\') >= 6);
      });
}
}
}
