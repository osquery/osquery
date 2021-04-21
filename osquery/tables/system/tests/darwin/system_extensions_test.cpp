/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <boost/property_tree/json_parser.hpp>
#include <gtest/gtest.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/core/sql/query_data.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/utils/darwin/plist.h>

namespace pt = boost::property_tree;

namespace osquery {
namespace tables {

extern QueryData genExtensionsFromPtree(const pt::ptree& ptree);

class SystemExtensionTests : public testing::Test {};

TEST_F(SystemExtensionTests, test_parse_ptree) {
  pt::ptree ptree;
  std::stringstream ss;
  ss << "{ \"version\": \"1\", \"extensions\": [{ \"state\": "
        "\"activated_enabled\", "
        "\"categories\": [ \"com.apple.system_extension.network_extension\" ], "
        "\"originPath\": "
        "\"/Applications/LuLu.app/Contents/Library/SystemExtensions/com."
        "objective-see.lulu.extension.systemextension\", "
        "\"additionalLaunchdPlistEntries\": "
        "\"YnBsaXN0MDDUAQIDBAUGBwpYJHZlcnNpb25ZJGFyY2hpdmVyVCR0b3BYJG9iamVjdHMS"
        "AAGGoF8QD05TS2V5ZWRBcmNoaXZlctEICVRyb290gAGvEBULDBkaGxwdIyQlKzEyODlBQk"
        "NHSEtVJG51bGzTDQ4PEBQYV05TLmtleXNaTlMub2JqZWN0c1YkY2xhc3OjERITgAKAA4AE"
        "oxUWF4AFgAaACoAJW1Byb2Nlc3NUeXBlXE1hY2hTZXJ2aWNlc1xMYXVuY2hFdmVudHNbSW"
        "50ZXJhY3RpdmXTDQ4PHiAYoR+"
        "AB6EhgAiACV8QIVZCRzk3VUI0VEEuY29tLm9iamVjdGl2ZS1zZWUubHVsdQnSJicoKVokY"
        "2xhc3NuYW1lWCRjbGFzc2VzXE5TRGljdGlvbmFyeaIoKlhOU09iamVjdNMNDg8sLhihLYA"
        "LoS+"
        "ADIAJXxAsY29tLmFwcGxlLm5ldHdvcmtleHRlbnNpb24ucHJvdmlkZXIubWF0Y2hpbmfTD"
        "Q4P"
        "MzUYoTSADaE2gA6ACV8QIGNvbS5vYmplY3RpdmUtc2VlLmx1bHUuZXh0ZW5zaW9u0w0ODz"
        "o9G"
        "KI7PIAPgBCiPj+"
        "AEYAUgAlfEBFORUV4dGVuc2lvblBvaW50c18QGk5FUHJvdmlkZXJCdW5kbGVJZGVudGlma"
        "WVy"
        "0g4PREahRYASgBNfECZjb20uYXBwbGUubmV0d29ya2V4dGVuc2lvbi5maWx0ZXItZGF0Yd"
        "ImJ0lKV05TQXJyYXmiSSpfECBjb20ub2JqZWN0aXZlLXNlZS5sdWx1LmV4dGVuc2lvbgAI"
        "ABE"
        "AGgAkACkAMgA3AEkATABRAFMAawBxAHgAgACLAJIAlgCYAJoAnACgAKIApACmAKgAtADBA"
        "M4A2gDhAOMA5QDnAOkA6wEPARABFQEgASkBNgE5AUIBSQFLAU0BTwFRAVMBggGJAYsBjQG"
        "PAZEBk"
        "wG2Ab0BwAHCAcQBxwHJAcsBzQHhAf4CAwIFAgcCCQIyAjcCPwJCAAAAAAAAAgEAAAAAAAA"
        "ATAAAAAAAAAAAAAAAAAAAAmU=\", \"bundleVersion\": { "
        "\"CFBundleShortVersionString\": \"2.0.0\", \"CFBundleVersion\": "
        "\"2.0.0\" }, \"identifier\": \"com.objective-see.lulu.extension\", "
        "\"stagedBundleURL\": { \"relative\": "
        "\"file:///Library/SystemExtensions/B4A2DE3D-1047-4109-9878-"
        "CC8238F6DE29/com.objective-see.lulu.extension.systemextension/\" },  "
        "\"container\": { \"bundlePath\": \"/Applications/LuLu.app\" },  "
        "\"uniqueID\": \"B4A2DE3D-1047-4109-9878-CC8238F6DE29\", "
        "\"stagedCdhashes\": { \"bb21ef2b71632c7c01c2173e465b993aa565508a\": { "
        "\"cputype\": \"16777223\", \"cpusubtype\": \"3\" }}, \"references\": "
        "[{\"appIdentifier\": \"com.objective-see.lulu.app\", \"appRef\": "
        "\"file:///.file/id=6571367.25554446/\", \"teamID\": "
        "\"VBG97UB4TA\"}], \"teamID\": \"VBG97UB4TA\" }], \"developerMode\": "
        "\"0\", \"extensionPolicies\": \"\", \"bootUUID\": "
        "\"E7C066D9-19F4-4E47-8E1E-35E1C1434905\" }";

  try {
    pt::read_json(ss, ptree);
  } catch (std::exception& e) {
    // Force fail the test on exception
    ASSERT_TRUE(false);
  }

  QueryData results = genExtensionsFromPtree(ptree);
  ASSERT_EQ(results.size(), 1U);

  EXPECT_EQ(results[0]["state"], "activated_enabled");
  EXPECT_EQ(results[0]["category"],
            "com.apple.system_extension.network_extension");
  EXPECT_EQ(results[0]["identifier"], "com.objective-see.lulu.extension");
  EXPECT_EQ(results[0]["version"], "2.0.0");
  EXPECT_EQ(results[0]["UUID"], "B4A2DE3D-1047-4109-9878-CC8238F6DE29");
  EXPECT_EQ(results[0]["team"], "VBG97UB4TA");
  EXPECT_EQ(results[0]["path"],
            "/Applications/LuLu.app/Contents/Library/SystemExtensions/"
            "com.objective-see.lulu.extension.systemextension");
  EXPECT_EQ(results[0]["bundle_path"], "/Applications/LuLu.app");
  EXPECT_EQ(results[0]["mdm_managed"], "0");
}

TEST_F(SystemExtensionTests, test_parse_plist) {
  auto dbplist_path = getTestConfigDirectory() / "db.plist";
  if (!osquery::pathExists(dbplist_path)) {
    return;
  }

  pt::ptree ptree;
  if (!osquery::parsePlist(dbplist_path, ptree).ok()) {
    return;
  }

  QueryData results = genExtensionsFromPtree(ptree);
  ASSERT_EQ(results.size(), 1U);

  EXPECT_EQ(results[0]["state"], "activated_enabled");
  EXPECT_EQ(results[0]["category"],
            "com.apple.system_extension.network_extension");
  EXPECT_EQ(results[0]["identifier"], "com.objective-see.lulu.extension");
  EXPECT_EQ(results[0]["version"], "2.0.0");
  EXPECT_EQ(results[0]["UUID"], "B4A2XXXX-XXXX-XXXX-XXXX-XXXX38F6DE29");
  EXPECT_EQ(results[0]["team"], "ABCDXYZUV");
  EXPECT_EQ(results[0]["path"],
            "/Applications/LuLu.app/Contents/Library/SystemExtensions/"
            "com.objective-see.lulu.extension.systemextension");
  EXPECT_EQ(results[0]["bundle_path"], "/Applications/LuLu.app");
  EXPECT_EQ(results[0]["mdm_managed"], "0");
}

} // namespace tables
} // namespace osquery
