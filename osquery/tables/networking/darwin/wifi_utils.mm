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

#include <osquery/system.h>

#include "osquery/tables/networking/darwin/wifi_utils.h"

namespace osquery {
namespace tables {

std::string extractSsid(const CFDataRef& data) {
  if (data == nil) {
    return "";
  }
  std::stringstream ss;
  auto bytes = CFDataGetBytePtr(data);
  auto length = CFDataGetLength(data);
  for (CFIndex i = 0; i < length; i++) {
    if (i > 0 && i % 4 == 0) {
      ss << " ";
    }
    ss << std::setfill('0') << std::setw(2) << std::hex
       << (unsigned int)bytes[i];
  }
  return ss.str();
}

std::string getSecurityName(const CWSecurity cw) {
  switch (cw) {
  case kCWSecurityNone:
    return "Open";
  case kCWSecurityWEP:
    return "WEP";
  case kCWSecurityWPAPersonal:
    return "WPA Personal";
  case kCWSecurityWPAPersonalMixed:
    return "WPA Personal Mixed";
  case kCWSecurityWPA2Personal:
    return "WPA2 Personal";
  case kCWSecurityPersonal:
    return "Personal";
  case kCWSecurityDynamicWEP:
    return "Dynamic WEP";
  case kCWSecurityWPAEnterprise:
    return "WPA Enterprise";
  case kCWSecurityWPA2Enterprise:
    return "WPA2 Enterprise";
  case kCWSecurityEnterprise:
    return "Enterprise";
  case kCWSecurityUnknown:
  default:
    return "Unknown";
  }
}

int getChannelNumber(const CWChannel* cwc) {
  return (int)[cwc channelNumber];
}

int getChannelWidth(const CWChannel* cwc) {
  switch ([cwc channelWidth]) {
  case kCWChannelWidth20MHz:
    return 20;
  case kCWChannelWidth40MHz:
    return 40;
  case kCWChannelWidth80MHz:
    return 80;
  case kCWChannelWidth160MHz:
    return 160;
  case kCWChannelWidthUnknown:
  default:
    return -1;
  }
}

int getChannelBand(const CWChannel* cwc) {
  switch ([cwc channelBand]) {
  case kCWChannelBand2GHz:
    return 2;
  case kCWChannelBand5GHz:
    return 5;
  case kCWChannelBandUnknown:
  default:
    return -1;
  }
}

std::string getInterfaceModeName(const CWInterfaceMode cwim) {
  switch (cwim) {
  case kCWInterfaceModeStation:
    return "Station";
  case kCWInterfaceModeIBSS:
    return "IBSS";
  case kCWInterfaceModeHostAP:
    return "Host AP";
  case kCWInterfaceModeNone:
  default:
    return "None";
  }
}
}
}
