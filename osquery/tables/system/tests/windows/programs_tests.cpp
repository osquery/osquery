/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>
#include <osquery/core/system.h>
#include <osquery/database/database.h>
#include <osquery/registry/registry.h>
#include <osquery/tables/system/windows/programs.h>
#include <osquery/tests/test_util.h>

namespace osquery {
namespace tables {

class ProgramsTablesTest : public testing::Test {
 protected:
  void SetUp() override {
    platformSetup();
    registryAndPluginInit();
    initDatabasePluginForTesting();
  }
};

TEST_F(ProgramsTablesTest, test_decode_msi_registry_guid) {
  // Empty guid
  std::string emptyGUID = "";
  ASSERT_EQ(decodeMsiRegistryGuid(emptyGUID), "");

  // Invalid length
  std::string invalidCompactGUID = "{0D8797326E7E4114DAECB3B66B9CD045}";
  ASSERT_EQ(decodeMsiRegistryGuid(invalidCompactGUID), "");

  // Valid conversion
  std::string validCompactGUID = "0D8797326E7E4114DAECB3B66B9CD045";
  ASSERT_EQ(decodeMsiRegistryGuid(validCompactGUID),
            "{237978D0-E7E6-4114-ADCE-3B6BB6C90D54}");
}

TEST_F(ProgramsTablesTest, test_build_ms_resource_uris) {
  // Not an ms-resource string
  ASSERT_TRUE(buildMsResourceUris("Telegram Desktop", "Telegram").empty());
  ASSERT_TRUE(buildMsResourceUris("ms-resource:", "Microsoft.Todos").empty());

  // Bare key: default Resources map first, then rooted at the package
  std::vector<std::string> bareKey = {
      "ms-resource://Microsoft.Todos/Resources/app_name_ms_todo",
      "ms-resource://Microsoft.Todos/app_name_ms_todo"};
  ASSERT_EQ(
      buildMsResourceUris("ms-resource:app_name_ms_todo", "Microsoft.Todos"),
      bareKey);

  // Relative path containing a resource map
  std::vector<std::string> relativePath = {
      "ms-resource://Microsoft.WindowsCamera/Resources/LensSDK/Resources/"
      "AppStoreName",
      "ms-resource://Microsoft.WindowsCamera/LensSDK/Resources/AppStoreName"};
  ASSERT_EQ(buildMsResourceUris("ms-resource:LensSDK/Resources/AppStoreName",
                                "Microsoft.WindowsCamera"),
            relativePath);

  // Path rooted at the package
  std::vector<std::string> rootedPath = {
      "ms-resource://Microsoft.Todos/Resources/AppName"};
  ASSERT_EQ(
      buildMsResourceUris("ms-resource:/Resources/AppName", "Microsoft.Todos"),
      rootedPath);

  // Already a full URI
  std::vector<std::string> fullUri = {
      "ms-resource://Microsoft.YourPhone/YourPhone/Resources/AppName"};
  ASSERT_EQ(buildMsResourceUris(
                "ms-resource://Microsoft.YourPhone/YourPhone/Resources/AppName",
                "Microsoft.YourPhone"),
            fullUri);

  // No package name: only full URIs can be resolved
  ASSERT_TRUE(buildMsResourceUris("ms-resource:AppName", "").empty());
}

} // namespace tables
} // namespace osquery
