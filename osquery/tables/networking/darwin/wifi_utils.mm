/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <CoreFoundation/CoreFoundation.h>

#include <osquery/core/system.h>
#include <osquery/core/tables.h>
#include <osquery/tables/networking/darwin/wifi_utils.h>
#include <osquery/utils/conversions/darwin/cfdata.h>
#include <osquery/utils/conversions/darwin/cfnumber.h>
#include <osquery/utils/conversions/darwin/cfstring.h>

namespace osquery {
namespace tables {

std::string getPropertiesFromDictionary(const CFDictionaryRef& dict,
                                        const std::string& key) {
  std::string value;

  auto cfkey = CFStringCreateWithCString(
      kCFAllocatorDefault, key.c_str(), kCFStringEncodingUTF8);
  auto property = CFDictionaryGetValue(dict, cfkey);
  CFRelease(cfkey);

  if (property == nullptr) {
    return value;
  }

  if (CFGetTypeID(property) == CFNumberGetTypeID()) {
    value = stringFromCFNumber((CFDataRef)property);
  } else if (CFGetTypeID(property) == CFStringGetTypeID()) {
    value = stringFromCFString((CFStringRef)property);
  } else if (CFGetTypeID(property) == CFDataGetTypeID()) {
    value = stringFromCFData((CFDataRef)property);
  } else if (CFGetTypeID(property) == CFBooleanGetTypeID()) {
    value = (CFBooleanGetValue((CFBooleanRef)property)) ? "1" : "0";
  } else if (CFGetTypeID(property) == CFDateGetTypeID()) {
    auto unix_time = CFDateGetAbsoluteTime((CFDateRef)property) +
                     kCFAbsoluteTimeIntervalSince1970;
    value = INTEGER(std::llround(unix_time));
  }

  return value;
}

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
