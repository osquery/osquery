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

    // To get the network name we need to use the system profiler.
    // Since this is a performance hit, only do it if we need to.
    if (context.isColumnUsed("network_name")) {
      // Get Airport data from system profiler, in order to get the current
      // network name for systems that don't return it via CWWiFiClient.
      NSDictionary* __autoreleasing result;
      Status status = getSystemProfilerReport("SPAirPortDataType", result);
      if (!status.ok()) {
        LOG(ERROR) << "failed to get SPAirPortDataType config: "
                   << status.getMessage();
        result = [NSDictionary dictionary];
      }

      for (NSDictionary* item in [result objectForKey:@"_items"]) {
        // Get the item's airport intefaces, which will usually include at least
        // a wifi card and an Apple Wireless Direct Link (AWDL) interface.
        NSArray* airportInterfaces =
            [item objectForKey:@"spairport_airport_interfaces"];
        // Get the wifi interface (the one starting with "en").
        NSDictionary* wifiInterface = [[airportInterfaces
            filteredArrayUsingPredicate:
                [NSPredicate predicateWithFormat:@"_name BEGINSWITH %@", @"en"]]
            lastObject];
        // Add the network name to the map, indexed by interface name.
        wifiNetworks[[wifiInterface objectForKey:@"_name"]] = [[wifiInterface
            objectForKey:@"spairport_current_network_information"]
            objectForKey:@"_name"];
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
