/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <CoreWLAN/CoreWLAN.h>
#include <Foundation/Foundation.h>

#include <osquery/system.h>
#include <osquery/tables.h>

#include "osquery/tables/networking/darwin/wifi_utils.h"

#define DECLARE_TABLE_IMPLEMENTATION
#include <generated/tables/tbl_wifi_status_defs.hpp>

namespace osquery {
namespace tables {

QueryData genWifiStatus(QueryContext& context) {
  QueryData results;
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
  return results;
}
}
}
