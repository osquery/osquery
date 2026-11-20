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
  ASSERT_TRUE(buildMsResourceUris("ms-resource:/", "Microsoft.Todos").empty());

  // Bare key: default Resources map first, then rooted at the package, then
  // the same paths with an empty authority
  std::vector<std::string> bareKey = {
      "ms-resource://Microsoft.Todos/Resources/app_name_ms_todo",
      "ms-resource://Microsoft.Todos/app_name_ms_todo",
      "ms-resource:///Resources/app_name_ms_todo",
      "ms-resource:///app_name_ms_todo"};
  ASSERT_EQ(
      buildMsResourceUris("ms-resource:app_name_ms_todo", "Microsoft.Todos"),
      bareKey);

  // The scheme is case-insensitive, and surrounding whitespace is ignored
  ASSERT_EQ(
      buildMsResourceUris("MS-Resource:app_name_ms_todo", "Microsoft.Todos"),
      bareKey);
  ASSERT_EQ(buildMsResourceUris("  ms-resource:app_name_ms_todo\n",
                                "Microsoft.Todos"),
            bareKey);

  // Relative path containing a resource map
  std::vector<std::string> relativePath = {
      "ms-resource://Microsoft.WindowsCamera/Resources/LensSDK/Resources/"
      "AppStoreName",
      "ms-resource://Microsoft.WindowsCamera/LensSDK/Resources/AppStoreName",
      "ms-resource:///Resources/LensSDK/Resources/AppStoreName",
      "ms-resource:///LensSDK/Resources/AppStoreName"};
  ASSERT_EQ(buildMsResourceUris("ms-resource:LensSDK/Resources/AppStoreName",
                                "Microsoft.WindowsCamera"),
            relativePath);

  // Path rooted at the package
  std::vector<std::string> rootedPath = {
      "ms-resource://Microsoft.Todos/Resources/AppName",
      "ms-resource:///Resources/AppName"};
  ASSERT_EQ(
      buildMsResourceUris("ms-resource:/Resources/AppName", "Microsoft.Todos"),
      rootedPath);

  // Empty authority: the package's own resources, same as a rooted path
  ASSERT_EQ(buildMsResourceUris("ms-resource:///Resources/AppName",
                                "Microsoft.Todos"),
            rootedPath);

  // Full URI: tried exactly as written, because the authority names a
  // resource map, which isn't always named after the package
  std::vector<std::string> fullUri = {
      "ms-resource://Microsoft.YourPhone/YourPhone/Resources/AppName"};
  ASSERT_EQ(buildMsResourceUris(
                "ms-resource://Microsoft.YourPhone/YourPhone/Resources/AppName",
                "Microsoft.YourPhone"),
            fullUri);
  std::vector<std::string> otherMap = {
      "ms-resource://NotesApp/Resources/AppName"};
  ASSERT_EQ(buildMsResourceUris("ms-resource://NotesApp/Resources/AppName",
                                "Contoso.Notes"),
            otherMap);
  ASSERT_TRUE(buildMsResourceUris("ms-resource://Microsoft.YourPhone",
                                  "Microsoft.YourPhone")
                  .empty());

  // No package name: only the empty authority is tried
  std::vector<std::string> noPackageName = {"ms-resource:///Resources/AppName",
                                            "ms-resource:///AppName"};
  ASSERT_EQ(buildMsResourceUris("ms-resource:AppName", ""), noPackageName);
}

} // namespace tables
} // namespace osquery
