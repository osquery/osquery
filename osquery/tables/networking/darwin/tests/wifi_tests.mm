/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Foundation/Foundation.h>
#include <gtest/gtest.h>

#include "osquery/tests/test_util.h"

namespace osquery {
namespace tables {

void parseNetworks(const CFDictionaryRef& network, QueryData& results);

class WifiNetworksTest : public testing::Test {};

TEST_F(WifiNetworksTest, test_parse_wifi_networks) {
  std::string path = kTestDataPath + "test_airport.plist";

  auto plist = (__bridge CFDictionaryRef)
      [NSDictionary dictionaryWithContentsOfFile:@(path.c_str())];
  ASSERT_GE((long)CFDictionaryGetCount(plist), 1);
  std::string key{"KnownNetworks"};
  auto cfkey = CFStringCreateWithCString(kCFAllocatorDefault, key.c_str(),
                                         kCFStringEncodingUTF8);
  auto networks = (CFDictionaryRef)CFDictionaryGetValue(plist, cfkey);

  CFRelease(cfkey);

  QueryData results;
  auto count = CFDictionaryGetCount(networks);
  ASSERT_EQ((long)count, 2);
  std::vector<const void *> keys(count);
  std::vector<const void *> values(count);
  CFDictionaryGetKeysAndValues(networks, keys.data(), values.data());

  for (CFIndex i = 0; i < count; i++) {
    parseNetworks((CFDictionaryRef)values[i], results);
  }

  Row expected1 = {
      {"ssid", "2890d228 3487"},
      {"network_name", "High-Fi"},
      {"security_type", "WPA2 Personal"},
      {"last_connected", "1419843361"},
      {"passpoint", "0"},
      {"possibly_hidden", "0"},
      {"roaming", "0"},
      {"roaming_profile", "Single"},
      {"captive_portal", "0"},
      {"auto_login", "0"},
      {"temporarily_disabled", "0"},
      {"disabled", "0"},
  };
  Row expected2 = {
      {"ssid", "85e965a1 63ab"},
      {"network_name", "WhyFi"},
      {"security_type", "Open"},
      {"last_connected", "1437434883"},
      {"passpoint", "0"},
      {"possibly_hidden", "0"},
      {"roaming", "0"},
      {"roaming_profile", "None"},
      {"captive_portal", "1"},
      {"auto_login", "0"},
      {"temporarily_disabled", "0"},
      {"disabled", "0"},
  };

  for (const auto& column : expected1) {
    EXPECT_EQ(results.front()[column.first], column.second);
  }
  for (const auto& column : expected2) {
    EXPECT_EQ(results.back()[column.first], column.second);
  }
}

TEST_F(WifiNetworksTest, test_parse_legacy_wifi_networks) {
  std::string path = kTestDataPath + "test_airport_legacy.plist";

  auto plist = (__bridge CFDictionaryRef)
      [NSDictionary dictionaryWithContentsOfFile:@(path.c_str())];
  ASSERT_GE((long)CFDictionaryGetCount(plist), 1);
  std::string key{"RememberedNetworks"};
  auto cfkey = CFStringCreateWithCString(kCFAllocatorDefault, key.c_str(),
                                         kCFStringEncodingUTF8);
  auto networks = (CFArrayRef)CFDictionaryGetValue(plist, cfkey);

  CFRelease(cfkey);

  QueryData results;
  auto count = CFArrayGetCount(networks);
  ASSERT_EQ((long)count, 2);

  for (CFIndex i = 0; i < count; i++) {
    parseNetworks(
        (CFDictionaryRef)CFArrayGetValueAtIndex((CFArrayRef)networks, i),
        results);
  }

  Row expected1 = {
      {"ssid", "2890d228 3487"},
      {"network_name", "High-Fi"},
      {"security_type", "WPA2 Personal"},
      {"last_connected", "1419843361"},
      {"passpoint", "0"},
      {"possibly_hidden", "0"},
      {"roaming", "0"},
      {"roaming_profile", "Single"},
      {"captive_portal", "0"},
      {"auto_login", "0"},
      {"temporarily_disabled", "0"},
      {"disabled", "0"},
  };
  Row expected2 = {
      {"ssid", "85e965a1 63ab"},
      {"network_name", "WhyFi"},
      {"security_type", "Open"},
      {"last_connected", "1437434883"},
      {"passpoint", "0"},
      {"possibly_hidden", "0"},
      {"roaming", "0"},
      {"roaming_profile", "None"},
      {"captive_portal", "1"},
      {"auto_login", "0"},
      {"temporarily_disabled", "0"},
      {"disabled", "0"},
  };

  for (const auto& column : expected2) {
    EXPECT_EQ(results.front()[column.first], column.second);
  }
  for (const auto& column : expected1) {
    EXPECT_EQ(results.back()[column.first], column.second);
  }
}
}
}
