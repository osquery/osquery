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

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/filesystem/filesystem.h>
#include <osquery/logger/logger.h>
#include <osquery/sql/sql.h>
#include <osquery/tables/networking/darwin/wifi_utils.h>
#include <osquery/utils/conversions/darwin/cfstring.h>

namespace osquery {
namespace tables {

static const std::string kAirPortPreferencesPath =
    "/Library/Preferences/SystemConfiguration/"
    "com.apple.airport.preferences.plist";

static const std::string kAirPortPrefPathPostCatalina =
    "/Library/Preferences/com.apple.wifi.known-networks.plist";

// In 10.14 and prior, there was an "auto_login" key.
const std::map<std::string, std::string> kKnownWifiNetworkKeysPreCatalina = {
    {"auto_login", "AutoLogin"}, {"last_connected", "LastConnected"}};

const std::map<std::string, std::string> kKnownWifiNetworkKeysCommon = {
    {"ssid", "SSID"},
    {"network_name", "SSIDString"},
    {"security_type", "SecurityType"},
    {"roaming_profile", "RoamingProfileType"},
    {"captive_portal", "Captive"},
    {"roaming", "SPRoaming"},
    {"passpoint", "Passpoint"},
    {"possibly_hidden", "PossiblyHiddenNetwork"},
    {"disabled", "Disabled"},
    {"temporarily_disabled", "TemporarilyDisabled"}};

// The name of the "last_connected" key changed in 10.15.
const std::map<std::string, std::string> kKnownWifiNetworkKeysPostCatalina = {
    {"last_connected", "LastAutoJoinAt"}};

// Adjust the keys to read, based on the version of macOS
Status getKnownWifiNetworkKeys(std::map<std::string, std::string>& keys) {
  auto qd = SQL::selectAllFrom("os_version");
  if (qd.size() != 1) {
    return Status(-1, "Couldn't determine macOS version");
  }

  // Begin with macOS-version-specific keys:
  keys = (qd.front().at("major") < "11" && qd.front().at("minor") < "15")
             ? kKnownWifiNetworkKeysPreCatalina
             : kKnownWifiNetworkKeysPostCatalina;

  // Then include the common keys (not unique to any particular macOS version):
  // C++17 equivalent: keys.merge(kKnownWifiNetworkKeysCommon);
  keys.insert(kKnownWifiNetworkKeysCommon.begin(),
              kKnownWifiNetworkKeysCommon.end());

  return Status(0, "ok");
}

// Check if we are running on macOS 10.9, where the top-level key in the plist
//  was different
Status getKnownNetworksKey(std::string& key) {
  auto qd = SQL::selectAllFrom("os_version");
  if (qd.size() != 1) {
    return Status(-1, "Couldn't determine macOS version");
  }

  key = (qd.front().at("major") == "10" && qd.front().at("minor") == "9")
            ? "RememberedNetworks"
            : "KnownNetworks";
  return Status(0, "ok");
}

std::string extractNetworkProperties(const CFTypeRef& property) {
  if (CFGetTypeID(property) == CFDataGetTypeID()) {
    return extractSsid((CFDataRef)property);
  } else if (CFGetTypeID(property) == CFDateGetTypeID()) {
    auto unix_time = CFDateGetAbsoluteTime((CFDateRef)property) +
                     kCFAbsoluteTimeIntervalSince1970;
    return INTEGER(std::llround(unix_time));
  } else if (CFGetTypeID(property) == CFBooleanGetTypeID()) {
    return (CFBooleanGetValue((CFBooleanRef)property)) ? INTEGER(1)
                                                       : INTEGER(0);
  } else if (CFGetTypeID(property) == CFStringGetTypeID()) {
    return stringFromCFString((CFStringRef)property);
  } else {
    return ""; // Cannot determine CFTypeRef
  }
}

void parseNetworks(const CFDictionaryRef& network, QueryData& results) {
  if (network == nullptr || CFGetTypeID(network) != CFDictionaryGetTypeID() ||
      CFDictionaryGetCount(network) == 0) {
    return;
  }

  std::map<std::string, std::string> keys;
  auto status = getKnownWifiNetworkKeys(keys);
  if (!status.ok()) {
    VLOG(1) << status.getMessage();
    return;
  }

  Row r;
  for (const auto& kv : keys) {
    auto key = CFStringCreateWithCString(
        kCFAllocatorDefault, kv.second.c_str(), kCFStringEncodingUTF8);
    CFTypeRef value = nullptr;
    if (key != nullptr) {
      if (CFDictionaryGetValueIfPresent(network, key, &value)) {
        r[kv.first] = extractNetworkProperties(value);
      }
      CFRelease(key);
    }
  }
  results.push_back(r);
}

QueryData parseBigSur(const std::string& path) {
  QueryData results;
  @autoreleasepool {
    auto plist = (__bridge CFDictionaryRef)
        [NSDictionary dictionaryWithContentsOfFile:@(path.c_str())];
    if (plist == nullptr || CFDictionaryGetCount(plist) == 0) {
      VLOG(1) << "cannot open plist";
      return results;
    }

    auto count = CFDictionaryGetCount(plist);
    std::vector<const void*> keys(count);
    std::vector<const void*> values(count);
    CFDictionaryGetKeysAndValues(plist, keys.data(), values.data());
    for (CFIndex i = 0; i < count; i++) {
      if (CFGetTypeID(keys[i]) == CFStringGetTypeID()) {
        Row r;
        auto key = stringFromCFString((CFStringRef)keys[i]);
        std::string delim = "wifi.network.ssid.";
        auto ssid = key.erase(0, key.find(delim) + delim.length());
        r["network_name"] = ssid;
        auto cfkey = CFStringCreateWithCString(
            kCFAllocatorDefault, "SSID", kCFStringEncodingUTF8);
        if (cfkey != nullptr) {
          auto ssid_data =
              CFDictionaryGetValue((CFDictionaryRef)values[i], cfkey);
          r["ssid"] = extractSsid((CFDataRef)ssid_data);
          CFRelease(cfkey);
        }

        r["security_type"] = getPropertiesFromDictionary(
            (CFDictionaryRef const&)values[i], "SupportedSecurityTypes");
        r["possibly_hidden"] = getPropertiesFromDictionary(
            (CFDictionaryRef const&)values[i], "Hidden");
        r["add_reason"] = getPropertiesFromDictionary(
            (CFDictionaryRef const&)values[i], "AddReason");
        r["added_at"] = getPropertiesFromDictionary(
            (CFDictionaryRef const&)values[i], "AddedAt");
        r["personal_hotspot"] = getPropertiesFromDictionary(
            (CFDictionaryRef const&)values[i], "PersonalHotspot");

        cfkey = CFStringCreateWithCString(
            kCFAllocatorDefault, "AutoJoinDisabled", kCFStringEncodingUTF8);
        if (cfkey != nullptr) {
          r["auto_join"] = (CFDictionaryContainsKey(
                               (CFDictionaryRef const&)values[i], cfkey))
                               ? "0"
                               : "1";
          CFRelease(cfkey);
        }

        cfkey = CFStringCreateWithCString(
            kCFAllocatorDefault, "CaptiveProfile", kCFStringEncodingUTF8);
        CFTypeRef captive = nullptr;
        if (cfkey != nullptr) {
          if (CFDictionaryGetValueIfPresent(
                  (CFDictionaryRef)values[i], cfkey, &captive)) {
            r["captive_portal"] = getPropertiesFromDictionary(
                (CFDictionaryRef const&)captive, "CaptiveNetwork");
            r["captive_login_date"] = getPropertiesFromDictionary(
                (CFDictionaryRef const&)captive, "CaptiveWebSheetLoginDate");
            r["was_captive_network"] = getPropertiesFromDictionary(
                (CFDictionaryRef const&)captive, "NetworkWasCaptive");
          }
          CFRelease(cfkey);
        }

        cfkey = CFStringCreateWithCString(
            kCFAllocatorDefault, "__OSSpecific__", kCFStringEncodingUTF8);
        CFTypeRef oss = nullptr;
        if (cfkey != nullptr) {
          if (CFDictionaryGetValueIfPresent(
                  (CFDictionaryRef)values[i], cfkey, &oss)) {
            r["roaming_profile"] = getPropertiesFromDictionary(
                (CFDictionaryRef const&)oss, "RoamingProfileType");
            r["temporarily_disabled"] = getPropertiesFromDictionary(
                (CFDictionaryRef const&)oss, "TemporarilyDisabled");
          }
          CFRelease(cfkey);
        }
        results.push_back(r);
      }
    }
  }
  return results;
}

inline bool isBigSurOrHigher() {
  NSProcessInfo* processInfo = [NSProcessInfo processInfo];
  static NSOperatingSystemVersion big_sur = {11, 0, 0};
  static NSOperatingSystemVersion big_sur_sys_compat = {10, 16, 0};

  return [processInfo isOperatingSystemAtLeastVersion:(big_sur)] ||
         [processInfo isOperatingSystemAtLeastVersion:(big_sur_sys_compat)];
}

QueryData genKnownWifiNetworks(QueryContext& context) {
  std::string key;
  auto status = getKnownNetworksKey(key);
  if (!status.ok()) {
    VLOG(1) << status.getMessage();
    return {};
  }

  std::string p = isBigSurOrHigher() ? kAirPortPrefPathPostCatalina
                                     : kAirPortPreferencesPath;
  boost::filesystem::path path = p;
  if (!pathExists(path).ok()) {
    VLOG(1) << "Airport preferences file not found: " << p;
    return {};
  }

  // drop privileges if needed
  auto dropper = DropPrivileges::get();
  dropper->dropToParent(path);

  if (!readFile(path)) {
    VLOG(1) << "Unable to read file: " << p;
    return {};
  }

  if (isBigSurOrHigher()) {
    return parseBigSur(p);
  }

  QueryData results;
  @autoreleasepool {
    auto plist = (__bridge CFDictionaryRef)
        [NSDictionary dictionaryWithContentsOfFile:@(p.c_str())];
    if (plist == nullptr || CFDictionaryGetCount(plist) == 0) {
      return {};
    }
    auto cfkey = CFStringCreateWithCString(
        kCFAllocatorDefault, key.c_str(), kCFStringEncodingUTF8);
    CFTypeRef networks = CFDictionaryGetValue(plist, cfkey);
    CFRelease(cfkey);
    if (networks == nullptr) {
      VLOG(1) << "Key not found : " << key;
      return {};
    }

    if (CFGetTypeID(networks) == CFArrayGetTypeID()) {
      auto count = CFArrayGetCount((CFArrayRef)networks);
      for (CFIndex i = 0; i < count; i++) {
        parseNetworks(
            (CFDictionaryRef)CFArrayGetValueAtIndex((CFArrayRef)networks, i),
            results);
      }
    } else if (CFGetTypeID(networks) == CFDictionaryGetTypeID()) {
      auto count = CFDictionaryGetCount((CFDictionaryRef)networks);
      std::vector<const void*> keys(count);
      std::vector<const void*> values(count);
      CFDictionaryGetKeysAndValues(
          (CFDictionaryRef)networks, keys.data(), values.data());
      for (CFIndex i = 0; i < count; i++) {
        parseNetworks((CFDictionaryRef)values[i], results);
      }
    }
  }
  return results;
}
}
}
