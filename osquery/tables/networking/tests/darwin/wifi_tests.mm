/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#include <gtest/gtest.h>

#include <osquery/config/tests/test_utils.h>
#include <osquery/core/sql/query_data.h>
#include <osquery/core/system.h>
#include <osquery/registry/registry_factory.h>
#include <osquery/sql/sql.h>

namespace osquery {
namespace tables {

void parseNetworks(const CFDictionaryRef& network, QueryData& results);
QueryData parseBigSur(const std::string& path);

class WifiNetworksTest : public testing::Test {
 protected:
  void SetUp() {
    platformSetup();
    registryAndPluginInit();
  }
};

TEST_F(WifiNetworksTest, test_parse_big_sur) {
  auto file = "test_airport_big_sur.plist";
  std::string path = (getTestConfigDirectory() / file).string();

  auto results = parseBigSur(path);
  ASSERT_EQ(results.size(), 3U);

  Row expected1 = {
      {"ssid", "4e657477 6f726b"},
      {"network_name", "Network"},
      {"security_type", "WPA/WPA2 Personal"},
      {"possibly_hidden", "0"},
      {"roaming_profile", "Dual"},
      {"temporarily_disabled", "0"},
      {"add_reason", "WiFi Menu"},
      {"added_at", "1640281275"},
      {"captive_portal", "0"},
      {"captive_login_date", ""},
      {"was_captive_network", ""},
      {"auto_join", "1"},
      {"personal_hotspot", ""},
  };

  Row expected2 = {
      {"ssid", "53746172 6275636b 7320496e 646961"},
      {"network_name", "Starbucks India"},
      {"security_type", "Open"},
      {"possibly_hidden", "0"},
      {"roaming_profile", "Dual"},
      {"temporarily_disabled", "0"},
      {"add_reason", "WiFi Menu"},
      {"added_at", "1643096288"},
      {"captive_portal", "1"},
      {"captive_login_date", ""},
      {"was_captive_network", ""},
      {"auto_join", "0"},
      {"personal_hotspot", ""},
  };

  Row expected3 = {
      {"ssid", "534253"},
      {"network_name", "SBS"},
      {"security_type", "WPA2/WPA3 Personal"},
      {"possibly_hidden", "0"},
      {"roaming_profile", "Multi"},
      {"temporarily_disabled", "0"},
      {"add_reason", "WiFi Menu"},
      {"added_at", "1638682885"},
      {"captive_portal", "0"},
      {"captive_login_date", ""},
      {"was_captive_network", ""},
      {"auto_join", "1"},
      {"personal_hotspot", ""},
  };

  for (auto&& testRow : results) {
    if (testRow["ssid"] == "4e657477 6f726b") {
      for (const auto& column : expected1) {
        EXPECT_EQ(testRow[column.first], column.second);
      }
    } else if (testRow["ssid"] == "53746172 6275636b 7320496e 646961") {
      for (const auto& column : expected2) {
        EXPECT_EQ(testRow[column.first], column.second);
      }
    } else if (testRow["ssid"] == "534253") {
      for (const auto& column : expected3) {
        EXPECT_EQ(testRow[column.first], column.second);
      }
    } else {
      FAIL() << "Unexpected data was read from airport.plist.";
    }
  }
}

TEST_F(WifiNetworksTest, test_parse_wifi_networks) {
  // the keys and values of the plist file have changed with new versions of
  // macOS, so the version of the test input file has to be consistent
  auto qd = SQL::selectAllFrom("os_version");
  ASSERT_EQ(qd.size(), 1);

  std::string file =
      (qd.front().at("major") < "11" && qd.front().at("minor") < "15")
          ? "test_airport_pre_macOS_10.15.plist"
          : "test_airport.plist";
  std::string path = (getTestConfigDirectory() / file).string();

  auto plist = (__bridge CFDictionaryRef)
      [NSDictionary dictionaryWithContentsOfFile:@(path.c_str())];
  ASSERT_NE(plist, nullptr);
  ASSERT_GE((long)CFDictionaryGetCount(plist), 1);
  std::string key = "KnownNetworks";
  auto cfkey = CFStringCreateWithCString(
      kCFAllocatorDefault, key.c_str(), kCFStringEncodingUTF8);
  auto networks = (CFDictionaryRef)CFDictionaryGetValue(plist, cfkey);

  CFRelease(cfkey);

  QueryData results;
  auto count = CFDictionaryGetCount(networks);
  ASSERT_EQ((long)count, 2);
  std::vector<const void*> keys(count);
  std::vector<const void*> values(count);
  CFDictionaryGetKeysAndValues(networks, keys.data(), values.data());

  for (CFIndex i = 0; i < count; i++) {
    parseNetworks((CFDictionaryRef)values[i], results);
  }
  ASSERT_EQ(results.size(), 2U);

  Row expected1 = {
      {"ssid", "85e965a1 63ab"},
      {"network_name", "WhyFi"},
      {"security_type", "Open"},
      {"last_connected", "1437434883"},
      {"passpoint", "0"},
      {"possibly_hidden", "0"},
      {"roaming", "0"},
      {"roaming_profile", "None"},
      {"captive_portal", "1"},
      {"temporarily_disabled", "0"},
      {"disabled", "0"},
  };
  Row expected2 = {
      {"ssid", "2890d228 3487"},
      {"network_name", "High-Fi"},
      {"security_type", "WPA2 Personal"},
      {"last_connected", "1419843361"},
      {"passpoint", "0"},
      {"possibly_hidden", "0"},
      {"roaming", "0"},
      {"roaming_profile", "Single"},
      {"captive_portal", "0"},
      {"temporarily_disabled", "0"},
      {"disabled", "0"},
  };

  // Pre-macOS 10.15, there was also an auto_login field to read
  if (qd.front().at("major") < "11" && qd.front().at("minor") < "15") {
    expected1.insert(std::pair<std::string, RowData>("auto_login", "0"));
    expected2.insert(std::pair<std::string, RowData>("auto_login", "0"));
  }

  // The order of keys returned from parsing a plist file using
  // CFDictionaryGetKeysAndValues() is deterministic, but not consistent across
  // versions of macOS. I.e., the data in keys[0] and keys[1] are returned in
  // a different order on macOS 10.15 than on 10.14 and earlier. To test that
  // results[] rows' contents are equal to that of the expected rows in this
  // test source, we first must peek at the value of the first column to match
  // the order in which the keys were read from the plist file by the API.
  for (auto&& testRow : results) {
    if (testRow["ssid"] == "85e965a1 63ab") {
      for (const auto& column : expected1) {
        EXPECT_EQ(testRow[column.first], column.second);
      }
    } else if (testRow["ssid"] == "2890d228 3487") {
      for (const auto& column : expected2) {
        EXPECT_EQ(testRow[column.first], column.second);
      }
    } else {
      FAIL() << "Unexpected data was read from airport.plist.";
    }
  }
}
}
}
