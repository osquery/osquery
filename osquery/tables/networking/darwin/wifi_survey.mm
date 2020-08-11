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

#include "osquery/tables/networking/darwin/wifi_utils.h"

namespace osquery {
namespace tables {

QueryData genWifiScan(QueryContext& context) {
  QueryData results;
  @autoreleasepool {
    NSArray<CWInterface*>* interfaces =
        [[CWWiFiClient sharedWiFiClient] interfaces];
    if (interfaces == nil || [interfaces count] == 0) {
      return results;
    }
    for (CWInterface* interface in interfaces) {
      NSSet<CWNetwork*>* networks =
          [interface scanForNetworksWithName:nil error:nil];

      for (CWNetwork* network in networks) {
        Row r;
        r["interface"] = [[interface interfaceName] UTF8String];
        r["ssid"] = extractSsid((__bridge CFDataRef)[network ssidData]);
        auto bssid = [network bssid];
        if (bssid != nullptr) {
          r["bssid"] = [bssid UTF8String];
        }
        r["network_name"] = [[network ssid] UTF8String];
        NSString* country_code = [network countryCode];
        if (country_code != nil) {
          r["country_code"] = [country_code UTF8String];
        }
        r["rssi"] = INTEGER([network rssiValue]);
        r["noise"] = INTEGER([network noiseMeasurement]);
        CWChannel* cwc = [network wlanChannel];
        if (cwc != nil) {
          r["channel"] = INTEGER(getChannelNumber(cwc));
          r["channel_width"] = INTEGER(getChannelWidth(cwc));
          r["channel_band"] = INTEGER(getChannelBand(cwc));
        }
        results.push_back(r);
      }
    }
  }
  return results;
}
}
}
