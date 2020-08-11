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
#include <osquery/tables/networking/darwin/wifi_utils.h>

namespace osquery {
namespace tables {

QueryData genWifiStatus(QueryContext& context) {
  QueryData results;
  @autoreleasepool {
    std::string interfaceName = "en0";
    NSArray<CWInterface*>* interfaces =
        [[CWWiFiClient sharedWiFiClient] interfaces];
    if (interfaces == nil || [interfaces count] == 0) {
      return results;
    }
    for (CWInterface* interface in interfaces) {
      Row r;
      r["interface"] = std::string([[interface interfaceName] UTF8String]);
      r["ssid"] = extractSsid((__bridge CFDataRef)[interface ssidData]);
      NSString* strptr = [interface bssid];
      if (strptr != nil) {
        r["bssid"] = std::string([strptr UTF8String]);
      }
      strptr = [interface ssid];
      if (strptr != nil) {
        r["network_name"] = std::string([strptr UTF8String]);
      }
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
