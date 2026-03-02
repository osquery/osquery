/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <CoreWLAN/CoreWLAN.h>
#include <Foundation/Foundation.h>
#include <SystemConfiguration/SystemConfiguration.h>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/networking/darwin/wifi_utils.h>
#include <osquery/utils/darwin/system_profiler.h>

namespace osquery {
namespace tables {

static const std::string kKnownNetworksPlistPath =
    "/Library/Preferences/com.apple.wifi.known-networks.plist";

/**
 * @brief Try to get the current SSID from SCDynamicStore's AirPort state.
 *
 * On some macOS versions, the AirPort state in the SystemConfiguration dynamic
 * store may contain the SSID even when CoreWLAN redacts it due to Location
 * Services restrictions.
 *
 * @param interfaceName the network interface name (e.g., "en0").
 * @return the SSID string, or nil if not available.
 */
static NSString* getSSIDFromDynamicStore(NSString* interfaceName) {
  SCDynamicStoreRef store =
      SCDynamicStoreCreate(nullptr, CFSTR("osquery"), nullptr, nullptr);
  if (store == nullptr) {
    return nil;
  }

  CFStringRef key = SCDynamicStoreKeyCreateNetworkInterfaceEntity(
      nullptr,
      kSCDynamicStoreDomainState,
      (__bridge CFStringRef)interfaceName,
      kSCEntNetAirPort);

  NSDictionary* info =
      (__bridge_transfer NSDictionary*)SCDynamicStoreCopyValue(store, key);
  CFRelease(key);
  CFRelease(store);

  if (info == nil) {
    return nil;
  }

  NSString* ssid = [info objectForKey:@"SSID_STR"];
  if (ssid != nil && [ssid length] > 0) {
    return ssid;
  }

  return nil;
}

/**
 * @brief Infer the current network name from the known-networks plist.
 *
 * Reads /Library/Preferences/com.apple.wifi.known-networks.plist (Big Sur+)
 * and returns the network with the most recent join timestamp. This works as
 * a heuristic for identifying the currently connected network without requiring
 * Location Services, which osqueryd cannot obtain as a launchd daemon.
 *
 * @return the inferred network name, or nil if inference failed.
 */
static NSString* inferNetworkNameFromKnownNetworks() {
  NSDictionary* plist = [NSDictionary
      dictionaryWithContentsOfFile:@(kKnownNetworksPlistPath.c_str())];
  if (plist == nil) {
    VLOG(1) << "Could not read known-networks plist at "
            << kKnownNetworksPlistPath;
    return nil;
  }

  NSString* prefix = @"wifi.network.ssid.";
  NSString* bestName = nil;
  NSDate* bestDate = nil;

  for (NSString* key in plist) {
    if (![key hasPrefix:prefix]) {
      continue;
    }

    NSDictionary* networkInfo = [plist objectForKey:key];
    if (![networkInfo isKindOfClass:[NSDictionary class]]) {
      continue;
    }

    NSDate* systemJoin = [networkInfo objectForKey:@"JoinedBySystemAt"];
    NSDate* userJoin = [networkInfo objectForKey:@"JoinedByUserAt"];

    // Use the most recent of the two join timestamps.
    NSDate* latestJoin = nil;
    if (systemJoin != nil && userJoin != nil) {
      latestJoin = [systemJoin laterDate:userJoin];
    } else if (systemJoin != nil) {
      latestJoin = systemJoin;
    } else {
      latestJoin = userJoin;
    }

    if (latestJoin != nil &&
        (bestDate == nil ||
         [latestJoin compare:bestDate] == NSOrderedDescending)) {
      bestDate = latestJoin;
      bestName = [key substringFromIndex:[prefix length]];
    }
  }

  return bestName;
}

QueryData genWifiStatus(QueryContext& context) {
  QueryData results;
  @autoreleasepool {
    // Get the list of Wifi interfaces on the system.
    NSArray<CWInterface*>* interfaces =
        [[CWWiFiClient sharedWiFiClient] interfaces];
    if (interfaces == nil || [interfaces count] == 0) {
      return results;
    }

    // Var to hold a map of interface names to network names.
    NSMutableDictionary* wifiNetworks = [NSMutableDictionary dictionary];

    // Resolve network names using a cascade of methods, from fastest to
    // slowest. On macOS 14.4+, CoreWLAN redacts the SSID unless the process
    // has Location Services authorization, which launchd daemons cannot
    // obtain. We try lightweight alternatives before the expensive system
    // profiler fallback.
    if (context.isColumnUsed("network_name")) {
      // Method 1: SCDynamicStore AirPort state (per-interface, fast).
      // The SystemConfiguration dynamic store may expose the SSID even when
      // CoreWLAN redacts it.
      for (CWInterface* interface in interfaces) {
        NSString* ifName = [interface interfaceName];
        NSString* ssid = getSSIDFromDynamicStore(ifName);
        if (ssid != nil) {
          VLOG(1) << "network_name \"" << [ssid UTF8String] << "\" for \""
                  << [ifName UTF8String]
                  << "\" inferred from system configuration dynamic store";
          wifiNetworks[ifName] = ssid;
        }
      }

      // Method 2: Known-networks plist inference (heuristic, fast).
      // Read the system's saved WiFi networks and pick the one with the most
      // recent join timestamp. Only attempt for interfaces that appear
      // connected (have an active channel) but whose name we haven't resolved.
      {
        NSString* inferredName = nil;
        for (CWInterface* interface in interfaces) {
          NSString* ifName = [interface interfaceName];
          if ([wifiNetworks objectForKey:ifName] != nil) {
            continue;
          }
          if ([interface wlanChannel] == nil) {
            continue; // Not connected, skip inference.
          }
          if (inferredName == nil) {
            inferredName = inferNetworkNameFromKnownNetworks();
          }
          if (inferredName != nil) {
            VLOG(1) << "network_name \"" << [inferredName UTF8String]
                    << "\" for \"" << [ifName UTF8String]
                    << "\" inferred from known networks";
            wifiNetworks[ifName] = inferredName;
          }
        }
      }

      // Method 3: System profiler (slow, authoritative fallback).
      // Only call if there are still connected interfaces without a name.
      //
      // On some versions of macOS the network name inferred from
      // SPAirPortDataType is "<redacted>".
      {
        BOOL needFallback = NO;
        for (CWInterface* interface in interfaces) {
          if ([interface wlanChannel] != nil &&
              [wifiNetworks objectForKey:[interface interfaceName]] == nil) {
            needFallback = YES;
            break;
          }
        }
        if (needFallback) {
          NSDictionary* __autoreleasing result;
          Status status = getSystemProfilerReport("SPAirPortDataType", result);
          if (!status.ok()) {
            LOG(ERROR) << "failed to get SPAirPortDataType config: "
                       << status.getMessage();
            result = [NSDictionary dictionary];
          }
          for (NSDictionary* item in [result objectForKey:@"_items"]) {
            NSArray* airportInterfaces =
                [item objectForKey:@"spairport_airport_interfaces"];
            NSDictionary* wifiInterface = [[airportInterfaces
                filteredArrayUsingPredicate:
                    [NSPredicate predicateWithFormat:@"_name BEGINSWITH %@",
                                                     @"en"]] lastObject];
            NSString* spIfName = [wifiInterface objectForKey:@"_name"];
            if (spIfName != nil &&
                [wifiNetworks objectForKey:spIfName] == nil) {
              NSString* networkName = [[wifiInterface
                  objectForKey:@"spairport_current_network_information"]
                  objectForKey:@"_name"];
              VLOG(1) << "network_name \"" << [networkName UTF8String]
                      << "\" for \"" << [spIfName UTF8String]
                      << "\" inferred from SPAirPortDataType";
              wifiNetworks[spIfName] = networkName;
            }
          }
        }
      }
    }

    for (CWInterface* interface in interfaces) {
      Row r;
      r["interface"] = std::string([[interface interfaceName] UTF8String]);
      r["ssid"] = extractSsid((__bridge CFDataRef)[interface ssidData]);
      NSString* strptr = [interface bssid];
      if (strptr != nil) {
        r["bssid"] = std::string([strptr UTF8String]);
      }

      NSString* networkName =
          [wifiNetworks objectForKey:[interface interfaceName]];
      if (networkName == nil) {
        networkName = @"";
      }
      r["network_name"] = std::string([networkName UTF8String]);

      NSString* country_code = [interface countryCode];
      if (country_code != nil) {
        r["country_code"] = std::string([country_code UTF8String]);
      }
      r["rssi"] = INTEGER([interface rssiValue]);
      r["noise"] = INTEGER([interface noiseMeasurement]);
      r["security_type"] = getSecurityName([interface security]);
      CWChannel* cwc = [interface wlanChannel];
      if (cwc != nil) {
        r["channel"] = INTEGER(getChannelNumber(cwc));
        r["channel_width"] = INTEGER(getChannelWidth(cwc));
        r["channel_band"] = INTEGER(getChannelBand(cwc));
      }
      r["transmit_rate"] = INTEGER([interface transmitRate]);
      r["mode"] = getInterfaceModeName([interface interfaceMode]);
      results.push_back(r);
    }
  }
  return results;
}
}
}
