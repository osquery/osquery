/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include "osquery/tables/system/darwin/iokit_utils.h"

namespace osquery {
namespace tables {

std::string getIOKitProperty(const CFMutableDictionaryRef& details,
                             const std::string& key) {
  std::string value;

  // Get a property from the device.
  auto cfkey = CFStringCreateWithCString(
      kCFAllocatorDefault, key.c_str(), kCFStringEncodingUTF8);
  auto property = CFDictionaryGetValue(details, cfkey);
  CFRelease(cfkey);

  // Several supported ways of parsing IOKit-encoded data.
  if (property) {
    if (CFGetTypeID(property) == CFNumberGetTypeID()) {
      value = stringFromCFNumber((CFDataRef)property);
    } else if (CFGetTypeID(property) == CFStringGetTypeID()) {
      value = stringFromCFString((CFStringRef)property);
    } else if (CFGetTypeID(property) == CFDataGetTypeID()) {
      value = stringFromCFData((CFDataRef)property);
    } else if (CFGetTypeID(property) == CFBooleanGetTypeID()) {
      value = (CFBooleanGetValue((CFBooleanRef)property)) ? "1" : "0";
    }
  }

  return value;
}
}
}
