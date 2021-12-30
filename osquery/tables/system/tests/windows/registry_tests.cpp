/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/algorithm/string/predicate.hpp>
#include <gtest/gtest.h>

#include <osquery/core/flags.h>
#include <osquery/core/system.h>
#include <osquery/registry/registry_interface.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/system/windows/registry.h>
#include <osquery/tests/test_util.h>

namespace osquery {
namespace tables {

class RegistryTablesTest : public testing::Test {
 protected:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }
};

const std::string kTestKey = "HKEY_LOCAL_MACHINE\\SOFTWARE";
const std::string kTestSpecificKey =
    "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Control "
    "Panel";
const std::string kInvalidTestKey = "HKEY_LOCAL_MACHINE\\PATH\\to\\madeup\\key";

TEST_F(RegistryTablesTest, test_registry_existing_key) {
  QueryData results;
  auto ret = queryKey(kTestKey, results);
  EXPECT_TRUE(ret.ok());
  EXPECT_TRUE(results.size() > 0);
}

TEST_F(RegistryTablesTest, test_expand_registry_globs) {
  std::set<std::string> results;
  auto s = expandRegistryGlobs(kTestSpecificKey + kRegSep + '%', results);
  ASSERT_TRUE(s.ok());
  EXPECT_FALSE(results.empty());

  // Calls should reset the output variable.
  s = expandRegistryGlobs("", results);
  EXPECT_TRUE(results.empty());
}

TEST_F(RegistryTablesTest, test_query_multiple_registry_keys) {
  QueryData test_results;
  auto s = queryMultipleRegistryKeys({kTestKey}, test_results);
  ASSERT_TRUE(s.ok());
  EXPECT_FALSE(test_results.empty());

  QueryData test_specific_results;
  s = queryMultipleRegistryKeys({kTestSpecificKey}, test_specific_results);
  ASSERT_TRUE(s.ok());
  EXPECT_FALSE(test_specific_results.empty());

  QueryData results;
  s = queryMultipleRegistryKeys({kTestKey, kTestSpecificKey}, results);
  ASSERT_TRUE(s.ok());
  EXPECT_EQ(results.size(), test_results.size() + test_specific_results.size());
}

TEST_F(RegistryTablesTest, test_query_multiple_registry_paths) {
  QueryData test_results;
  auto s = queryMultipleRegistryPaths({kTestKey}, test_results);
  ASSERT_TRUE(s.ok());
  EXPECT_FALSE(test_results.empty());

  QueryData test_specific_results;
  s = queryMultipleRegistryPaths({kTestSpecificKey}, test_specific_results);
  ASSERT_TRUE(s.ok());
  EXPECT_FALSE(test_specific_results.empty());

  QueryData results;
  s = queryMultipleRegistryPaths({kTestKey, kTestSpecificKey}, results);
  ASSERT_TRUE(s.ok());
  EXPECT_EQ(results.size(), test_results.size() + test_specific_results.size());
}

TEST_F(RegistryTablesTest, test_registry_non_existing_key) {
  QueryData results;
  auto ret = queryKey(kInvalidTestKey, results);
  EXPECT_FALSE(ret.ok());
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
  SQL result1("SELECT * FROM registry WHERE key = \"" + kTestKey + "\"");
  SQL result2("SELECT * FROM registry WHERE key = \"" + kTestSpecificKey +
              "\"");
  SQL combinedResults("SELECT * FROM registry WHERE key = \"" + kTestKey +
                      "\" OR key = \"" + kTestSpecificKey + "\"");

  EXPECT_TRUE(result1.rows().size() > 0);
  EXPECT_TRUE(result2.rows().size() > 0);
  EXPECT_TRUE(combinedResults.rows().size() ==
              result1.rows().size() + result2.rows().size());
  EXPECT_TRUE(std::includes(combinedResults.rows().begin(),
                            combinedResults.rows().end(),
                            result1.rows().begin(),
                            result1.rows().end()));
  EXPECT_TRUE(std::includes(combinedResults.rows().begin(),
                            combinedResults.rows().end(),
                            result2.rows().begin(),
                            result2.rows().end()));
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

TEST_F(RegistryTablesTest, test_registry_path_query_no_separators) {
  std::string testPath = "HKEY_LOCAL_MACHINE";
  SQL results("select * from registry where path like \"" + testPath + "%\"");
  EXPECT_TRUE(results.rows().size() > 1);
  std::for_each(
      results.rows().begin(), results.rows().end(), [&](const auto& row) {
        auto path = row.at("path");
        EXPECT_TRUE(boost::starts_with(path, testPath));
        EXPECT_TRUE(std::count(path.begin(), path.end(), '\\') == 1);
      });
}

TEST_F(RegistryTablesTest, test_registry_path_query_matches_key_data) {
  SQL keyResults("select * from registry where key = \"" + kTestKey + "\"");
  SQL pathResults("select * from registry where path like \"" + kTestKey +
                  kRegSep + "%\"");
  EXPECT_TRUE(keyResults.rows().size() > 1);
  EXPECT_TRUE(pathResults.rows().size() == keyResults.rows().size());
  std::for_each(
      keyResults.rows().begin(), keyResults.rows().end(), [&](const auto& row) {
        SQL results("select * from registry where path = \"" + row.at("path") +
                    "\"");
        EXPECT_TRUE(results.rows().size() == 1);
        EXPECT_TRUE(row == results.rows()[0]);
      });
}

TEST_F(RegistryTablesTest, test_get_username_from_key) {
  Status status;
  std::string username;
  std::set<std::string> badKeys = {
      "HKEY_USERS\\Some\\Key",
      "HKEY_USERS\\",
      "HKEY_USERS",
      "HKEY_LOCAL_MACHINE\\Some\\Key",
  };

  status = getUsernameFromKey("HKEY_USERS\\S-1-5-19\\Some\\Key", username);
  EXPECT_TRUE(status.ok());
  for (const auto& key : badKeys) {
    status = getUsernameFromKey(key, username);
    EXPECT_FALSE(status.ok());
  }
}

TEST_F(RegistryTablesTest, test_populate_subkeys_valid_key) {
  Status status;
  std::set<std::string> validKey = {"HKEY_CURRENT_USER\\AppEvents"};

  status = populateSubkeys(validKey, false);
  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(validKey.size() > 1);
}

TEST_F(RegistryTablesTest, test_populate_subkeys_invalid_key) {
  Status status;
  std::string invalidKey = "HKEY_LOCAL_MACHINE\\Some\\Key";
  std::set<std::string> badKey = {invalidKey};

  status = populateSubkeys(badKey, false);
  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(badKey.size() == 1);
  EXPECT_TRUE(badKey.count(invalidKey));
}

TEST_F(RegistryTablesTest, test_populate_subkeys_invalid_middle_key) {
  Status status;
  std::string validKey1 = "HKEY_LOCAL_MACHINE\\SYSTEM\\ResourceManager";
  std::string validKey2 = "HKEY_USERS\\.DEFAULT\\System";
  std::string invalidKey = "HKEY_LOCAL_MACHINE\\Some\\Key";
  const std::set<std::string> origKeys = {
      validKey1,
      invalidKey,
      validKey2,
  };

  std::set<std::string> keys{origKeys.cbegin(), origKeys.cend()};

  status = populateSubkeys(keys, false);
  EXPECT_TRUE(status.ok());
  EXPECT_TRUE(origKeys.size() < keys.size());
  keys.erase(validKey1);
  keys.erase(invalidKey);
  keys.erase(validKey2);
  EXPECT_TRUE(
      std::any_of(keys.begin(), keys.end(), [&](const std::string& key) {
        return boost::starts_with(key, validKey1);
      }));
  EXPECT_TRUE(
      std::none_of(keys.begin(), keys.end(), [&](const std::string& key) {
        return boost::starts_with(key, invalidKey);
      }));
  EXPECT_TRUE(
      std::any_of(keys.begin(), keys.end(), [&](const std::string& key) {
        return boost::starts_with(key, validKey2);
      }));
}
} // namespace tables
} // namespace osquery
