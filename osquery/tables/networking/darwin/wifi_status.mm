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

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/tables/networking/darwin/wifi_utils.h>
#include <osquery/utils/darwin/system_profiler.h>

namespace osquery {
namespace tables {

// Requires "Full Disk Access".
static const std::string kKnownNetworksPlistPath =
    "/Library/Preferences/com.apple.wifi.known-networks.plist";

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
    if (systemJoin != nil && ![systemJoin isKindOfClass:[NSDate class]]) {
      systemJoin = nil;
    }
    NSDate* userJoin = [networkInfo objectForKey:@"JoinedByUserAt"];
    if (userJoin != nil && ![userJoin isKindOfClass:[NSDate class]]) {
      userJoin = nil;
    }

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

    // To get the network name we may need to use the system profiler.
    // Since this is a performance hit, only do it if we need to.
    if (context.isColumnUsed("network_name")) {
      //
      // Method 1: If there's only one interface (most common scenario),
      // we'll attempt to extract the network name from the last joined of the
      // known networks. This method is faster and more accurate than the system
      // profiler method below. The system profiler method is returning
      // <redacted> on several macOS versions.
      //
      if ([interfaces count] == 1) {
        CWInterface* interface = interfaces[0];
        NSString* ifName = [interface interfaceName];
        // Interface must be connected.
        if ([interface wlanChannel] != nil) {
          NSString* inferredName = inferNetworkNameFromKnownNetworks();
          if (inferredName != nil) {
            wifiNetworks[ifName] = inferredName;
          }
        }
      }

      // Method 2: System profiler (slow, authoritative fallback).
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
