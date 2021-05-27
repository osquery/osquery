/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <gtest/gtest.h>

#include <boost/property_tree/json_parser.hpp>

#include <osquery/hashing/hashing.h>
#include <osquery/tables/applications/chrome/utils.h>

namespace osquery {

namespace tables {

namespace {

#ifdef WIN32
constexpr auto kTestProfilePath =
    "C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User Data\\Default";

constexpr auto kTestExtensionPath =
    "C:\\Users\\user\\AppData\\Local\\Google\\Chrome\\User "
    "Data\\Default\\Extensions\\extension\\1.00.0_0";

constexpr auto kTestProfilePreferences = R"PREFERENCES(
{
  "extensions": {
    "settings": {
      "extension_identifier1": {
        "from_webstore": true,
        "install_time": "13251308956895241",
        "path": "extension\\1.00.0_0",
        "state": 1
      },
      "extension_identifier2": {
        "from_webstore": false,
        "install_time": "13251308956895242",
        "path": "C:\\absolute\\path\\to\\extension\\1.00.0_0",
        "state": 0
      }
    }
  },
  "profile": { "name": "test" }
}
)PREFERENCES";

constexpr auto kOutOfProfileTestExtensionPath =
    "C:\\absolute\\path\\to\\extension\\1.00.0_0";

#else
constexpr auto kTestProfilePath = "/home/user/.config/google-chrome/Default";

constexpr auto kTestExtensionPath =
    "/home/user/.config/google-chrome/Default/Extensions/extension/1.00.0_0";

constexpr auto kTestProfilePreferences = R"PREFERENCES(
{
  "extensions": {
    "settings": {
      "extension_identifier1": {
        "from_webstore": true,
        "install_time": "13251308956895241",
        "path": "extension/1.00.0_0",
        "state": 1
      },
      "extension_identifier2": {
        "from_webstore": false,
        "install_time": "13251308956895242",
        "path": "/absolute/path/to/extension/1.00.0_0",
        "state": 0
      }
    }
  },
  "profile": { "name": "test" }
}
)PREFERENCES";

constexpr auto kOutOfProfileTestExtensionPath =
    "/absolute/path/to/extension/1.00.0_0";
#endif

constexpr auto kTestExtensionManifest = R"MANIFEST(
{
  "author": "Author",
  "background": { "persistent": "true" },
  "content_scripts": [
    {
      "js": [ "/js/1.js", "/js/2.js" ],
      "matches": [ "http://*/1*", "https://*/2*" ]
    },
    {
      "js": [ "/js/3.js", "/js/4.js" ],
      "matches": [ "http://*/3*", "https://*/4*" ]
    }
  ],
  "default_locale": "en",
  "current_locale": "en",
  "description": "Description",
  "key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmJNzUNVjS6Q1qe0NRqpmfX/oSJdgauSZNdfeb5RV1Hji21vX0TivpP5gq0fadwmvmVCtUpOaNUopgejiUFm/iKHPs0o3x7hyKk/eX0t2QT3OZGdXkPiYpTEC0f0p86SQaLoA2eHaOG4uCGi7sxLJmAXc6IsxGKVklh7cCoLUgWEMnj8ZNG2Y8UKG3gBdrpES5hk7QyFDMraO79NmSlWRNgoJHX6XRoY66oYThFQad8KL8q3pf3Oe8uBLKywohU0ZrDPViWHIszXoE9HEvPTFAbHZ1umINni4W/YVs+fhqHtzRJcaKJtsTaYy+cholu5mAYeTZqtHf6bcwJ8t9i2afwIDAQAB",
  "name": "Test extension",
  "permissions": [ "1", "2" ],
  "optional_permissions": [ "3", "4" ],
  "update_url": "https://clients2.google.com/service/update2/crx",
  "version": "1.00.0"
}
)MANIFEST";

constexpr auto kTestLocalizationFile = R"LOCALIZATION(
{
   "appdesc": {
      "message": "Description"
   },
   "appname": {
      "message": "Name"
   }
}
)LOCALIZATION";

const std::vector<std::pair<std::string, std::string>>
    kExpectedContentScriptsMatches = {
        {"/js/1.js", "http://*/1*"},
        {"/js/2.js", "http://*/1*"},
        {"/js/1.js", "https://*/2*"},
        {"/js/2.js", "https://*/2*"},
        {"/js/3.js", "http://*/3*"},
        {"/js/4.js", "http://*/3*"},
        {"/js/3.js", "https://*/4*"},
        {"/js/4.js", "https://*/4*"},
};

const std::unordered_map<std::string, std::string>
    kExpectedExtensionProperties = {
        {"name", "Test extension"},
        {"key",
         "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmJNzUNVjS6Q1qe0NRqpmfX/"
         "oSJdgauSZNdfeb5RV1Hji21vX0TivpP5gq0fadwmvmVCtUpOaNUopgejiUFm/"
         "iKHPs0o3x7hyKk/"
         "eX0t2QT3OZGdXkPiYpTEC0f0p86SQaLoA2eHaOG4uCGi7sxLJmAXc6IsxGKVklh7cCoLU"
         "gWEMnj8ZNG2Y8UKG3gBdrpES5hk7QyFDMraO79NmSlWRNgoJHX6XRoY66oYThFQad8KL8"
         "q3pf3Oe8uBLKywohU0ZrDPViWHIszXoE9HEvPTFAbHZ1umINni4W/"
         "YVs+fhqHtzRJcaKJtsTaYy+cholu5mAYeTZqtHf6bcwJ8t9i2afwIDAQAB"},
        {"update_url", "https://clients2.google.com/service/update2/crx"},
        {"version", "1.00.0"},
        {"author", "Author"},
        {"default_locale", "en"},
        {"current_locale", "en"},
        {"persistent", "true"},
        {"description", "Description"},
        {"permissions", "1, 2"},
        {"optional_permissions", "3, 4"},
        {"permissions_json", "{\"\":\"1\",\"\":\"2\"}\n"},
        {"optional_permissions_json", "{\"\":\"3\",\"\":\"4\"}\n"},
};

const std::string kExpectedComputedExtensionIdentifier{
    "cjpalhdlnbpafiamejdnhcphjbkeiagm"};

} // namespace

class ChromeUtilsTests : public ::testing::Test {};

TEST_F(ChromeUtilsTests, getChromeBrowserName) {
  auto browser_name = getChromeBrowserName(ChromeBrowserType::GoogleChrome);
  EXPECT_EQ(browser_name, "chrome");

  browser_name = getChromeBrowserName(ChromeBrowserType::Brave);
  EXPECT_EQ(browser_name, "brave");

  browser_name = getChromeBrowserName(ChromeBrowserType::Chromium);
  EXPECT_EQ(browser_name, "chromium");

  browser_name = getChromeBrowserName(ChromeBrowserType::Yandex);
  EXPECT_EQ(browser_name, "yandex");

  browser_name = getChromeBrowserName(ChromeBrowserType::Opera);
  EXPECT_EQ(browser_name, "opera");
}

TEST_F(ChromeUtilsTests, getExtensionContentScriptsMatches) {
  pt::iptree parsed_manifest;

  std::stringstream json_stream;
  json_stream << kTestExtensionManifest;
  pt::read_json(json_stream, parsed_manifest);

  auto entry_list = getExtensionContentScriptsMatches(parsed_manifest);
  ASSERT_EQ(entry_list.size(), kExpectedContentScriptsMatches.size());

  for (const auto& expected : kExpectedContentScriptsMatches) {
    const auto& script = std::get<0>(expected);
    const auto& match = std::get<1>(expected);

    auto entry_it =
        std::find_if(entry_list.begin(),
                     entry_list.end(),

                     [&script, &match](const ContentScriptsEntry& e) -> bool {
                       return (e.script == script && e.match == match);
                     });

    EXPECT_TRUE(entry_it != entry_list.end());
  }
}

TEST_F(ChromeUtilsTests, getExtensionProperties) {
  pt::iptree parsed_manifest;

  std::stringstream json_stream;
  json_stream << kTestExtensionManifest;
  pt::read_json(json_stream, parsed_manifest);

  ChromeProfile::Extension::Properties properties;
  auto status = getExtensionProperties(properties, parsed_manifest);
  ASSERT_TRUE(status.ok()) << "Failed to parse the extension properties: "
                           << status.getMessage();

  ASSERT_EQ(properties.size(), kExpectedExtensionProperties.size());

  for (const auto& expected : kExpectedExtensionProperties) {
    const auto& property_name = expected.first;
    const auto& expected_value = expected.second;

    auto property_it = properties.find(property_name);
    ASSERT_TRUE(property_it != properties.end());

    const auto& value = property_it->second;
    EXPECT_EQ(value, expected_value);
  }
}

TEST_F(ChromeUtilsTests, getProfileNameFromPreferences) {
  pt::iptree parsed_preferences;

  std::stringstream json_stream;
  json_stream << kTestProfilePreferences;
  pt::read_json(json_stream, parsed_preferences);

  std::string name;
  auto status = getProfileNameFromPreferences(name, parsed_preferences);
  EXPECT_TRUE(status.ok());
  EXPECT_EQ(name, "test");
}

TEST_F(ChromeUtilsTests, getStringLocalization) {
  pt::iptree parsed_localization;

  std::stringstream json_stream;
  json_stream << kTestLocalizationFile;
  pt::read_json(json_stream, parsed_localization);

  std::string localized_string;
  auto status = getStringLocalization(
      localized_string, parsed_localization, "test_string");

  EXPECT_TRUE(status.ok());
  EXPECT_EQ(localized_string, "test_string");

  status = getStringLocalization(
      localized_string, parsed_localization, "__MSG_appdesc__");

  EXPECT_TRUE(status.ok());
  EXPECT_EQ(localized_string, "Description");

  status = getStringLocalization(
      localized_string, parsed_localization, "__MSG_appname__");

  EXPECT_TRUE(status.ok());
  EXPECT_EQ(localized_string, "Name");

  status = getStringLocalization(
      localized_string, parsed_localization, "__MSG_ApPNamE__");

  EXPECT_TRUE(status.ok());
  EXPECT_EQ(localized_string, "Name");

  status = getStringLocalization(
      localized_string, parsed_localization, "__MSG_missing__");

  EXPECT_FALSE(status.ok());
  EXPECT_EQ(localized_string, "__MSG_missing__");
}

TEST_F(ChromeUtilsTests, getExtensionProfileSettings) {
  pt::iptree parsed_preferences;

  std::stringstream json_stream;
  json_stream << kTestProfilePreferences;
  pt::read_json(json_stream, parsed_preferences);

  ChromeProfile::Extension extension;
  auto status = getExtensionProfileSettings(extension.profile_settings,
                                            parsed_preferences,
                                            kTestExtensionPath,
                                            kTestProfilePath);

  auto state = getExtensionProfileSettingsValue(extension, "state");
  auto from_webstore =
      getExtensionProfileSettingsValue(extension, "from_webstore");

  auto install_time =
      getExtensionProfileSettingsValue(extension, "install_time");

  auto ref_identifier =
      getExtensionProfileSettingsValue(extension, "referenced_identifier");

  EXPECT_EQ(state, "1");
  EXPECT_EQ(from_webstore, "true");
  EXPECT_EQ(install_time, "13251308956895241");
  EXPECT_EQ(ref_identifier, "extension_identifier1");

  status = getExtensionProfileSettings(extension.profile_settings,
                                       parsed_preferences,
                                       kOutOfProfileTestExtensionPath,
                                       kTestProfilePath);

  state = getExtensionProfileSettingsValue(extension, "state");
  from_webstore = getExtensionProfileSettingsValue(extension, "from_webstore");
  install_time = getExtensionProfileSettingsValue(extension, "install_time");
  ref_identifier =
      getExtensionProfileSettingsValue(extension, "referenced_identifier");

  EXPECT_EQ(state, "0");
  EXPECT_EQ(from_webstore, "false");
  EXPECT_EQ(install_time, "13251308956895242");
  EXPECT_EQ(ref_identifier, "extension_identifier2");
}

TEST_F(ChromeUtilsTests, getExtensionFromSnapshot) {
  ChromeProfileSnapshot::Extension snapshot;
  snapshot.path = kTestExtensionPath;
  snapshot.manifest = kTestExtensionManifest;

  ChromeProfile::Extension extension;
  auto status = getExtensionFromSnapshot(extension, snapshot);
  ASSERT_TRUE(status.ok());

  EXPECT_EQ(extension.path, kTestExtensionPath);
  EXPECT_FALSE(extension.manifest_json.empty());

  // This is not yet initialized; the table code will update it
  // by calling getExtensionProfileSettings()
  EXPECT_FALSE(extension.referenced);

  auto expected_manifest_hash = hashFromBuffer(
      HASH_TYPE_SHA256, snapshot.manifest.c_str(), snapshot.manifest.size());

  EXPECT_EQ(extension.manifest_hash, expected_manifest_hash);

  // We have already checked getExtensionProperties and
  // getExtensionContentScriptsMatches, so just make sure
  // they are not empty
  EXPECT_EQ(extension.properties.size(), kExpectedExtensionProperties.size());

  EXPECT_EQ(extension.content_scripts_matches.size(),
            kExpectedContentScriptsMatches.size());

  // Also make sure that the computed identifier is correct
  ASSERT_TRUE(extension.opt_computed_identifier.has_value());

  const auto& computed_identifier = *extension.opt_computed_identifier;
  EXPECT_EQ(computed_identifier, kExpectedComputedExtensionIdentifier);
}

TEST_F(ChromeUtilsTests, getChromeProfilesFromSnapshotList) {
  ChromeProfileSnapshot::Extension ref_ext_snapshot;
  ref_ext_snapshot.path = kTestExtensionPath;
  ref_ext_snapshot.manifest = kTestExtensionManifest;

  ChromeProfileSnapshot::Extension unref_ext_snapshot;
  unref_ext_snapshot.path = std::string("/root/") + kTestExtensionPath;
  unref_ext_snapshot.manifest = kTestExtensionManifest;

  ChromeProfileSnapshot snapshot;
  snapshot.type = ChromeBrowserType::GoogleChrome;
  snapshot.path = kTestProfilePath;
  snapshot.preferences = kTestProfilePreferences;
  snapshot.uid = 1000;

  snapshot.referenced_extensions.insert(
      {ref_ext_snapshot.path, ref_ext_snapshot});

  snapshot.unreferenced_extensions.insert(
      {unref_ext_snapshot.path, unref_ext_snapshot});

  auto chrome_profile_list = getChromeProfilesFromSnapshotList({snapshot});
  ASSERT_EQ(chrome_profile_list.size(), 1U);

  const auto& profile = chrome_profile_list.at(0);
  EXPECT_EQ(profile.type, ChromeBrowserType::GoogleChrome);
  EXPECT_EQ(profile.name, "test");
  EXPECT_EQ(profile.uid, 1000);

  // As we have already tested the functions generating this data, just
  // make sure they are not empty
  ASSERT_EQ(profile.extension_list.size(), 2U);

  const auto& unreferenced_extension = profile.extension_list.at(0U);
  ASSERT_FALSE(unreferenced_extension.referenced);
  ASSERT_TRUE(unreferenced_extension.profile_settings.empty());

  const auto& referenced_extension = profile.extension_list.at(1U);
  ASSERT_TRUE(referenced_extension.referenced);
  ASSERT_FALSE(referenced_extension.profile_settings.empty());
}

TEST_F(ChromeUtilsTests, webkitTimeToUnixTimestamp) {
  auto timestamp_exp = webkitTimeToUnixTimestamp("13251227857389874");
  ASSERT_FALSE(timestamp_exp.isError());

  auto timestamp = timestamp_exp.take();
  ASSERT_EQ(timestamp, 1606754257);

  timestamp_exp = webkitTimeToUnixTimestamp("100");
  ASSERT_TRUE(timestamp_exp.isError());
  ASSERT_EQ(timestamp_exp.getErrorCode(), ConversionError::InvalidArgument);
}

TEST_F(ChromeUtilsTests, computeExtensionIdentifier) {
  ChromeProfile::Extension extension;
  auto identifier_exp = computeExtensionIdentifier(extension);
  ASSERT_TRUE(identifier_exp.isError());
  EXPECT_EQ(identifier_exp.getErrorCode(), ExtensionKeyError::MissingProperty);

  extension.properties.insert({"key", "hello, world!"});

  identifier_exp = computeExtensionIdentifier(extension);
  ASSERT_TRUE(identifier_exp.isError());
  EXPECT_EQ(identifier_exp.getErrorCode(), ExtensionKeyError::InvalidValue);

  extension.properties.clear();
  extension.properties.insert(
      {"key",
       "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmJNzUNVjS6Q1qe0NRqpmfX/"
       "oSJdgauSZNdfeb5RV1Hji21vX0TivpP5gq0fadwmvmVCtUpOaNUopgejiUFm/"
       "iKHPs0o3x7hyKk/"
       "eX0t2QT3OZGdXkPiYpTEC0f0p86SQaLoA2eHaOG4uCGi7sxLJmAXc6IsxGKVklh7cCoLUgW"
       "EMnj8ZNG2Y8UKG3gBdrpES5hk7QyFDMraO79NmSlWRNgoJHX6XRoY66oYThFQad8KL8q3pf"
       "3Oe8uBLKywohU0ZrDPViWHIszXoE9HEvPTFAbHZ1umINni4W/"
       "YVs+fhqHtzRJcaKJtsTaYy+cholu5mAYeTZqtHf6bcwJ8t9i2afwIDAQAB"});
  identifier_exp = computeExtensionIdentifier(extension);
  ASSERT_FALSE(identifier_exp.isError());

  auto identifier = identifier_exp.get();
  EXPECT_EQ(identifier, kExpectedComputedExtensionIdentifier);
}

} // namespace tables

} // namespace osquery
