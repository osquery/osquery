/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant 
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <boost/lexical_cast.hpp>

#include "osquery/core/conversions.h"

namespace osquery {

std::string stringFromCFString(const CFStringRef& cf_string) {
  // Access, then convert the CFString. CFStringGetCStringPtr is less-safe.
  CFIndex length = CFStringGetLength(cf_string);
  char* buffer = (char*)malloc(length + 1);
  if (!CFStringGetCString(
          cf_string, buffer, length + 1, kCFStringEncodingASCII)) {
    free(buffer);
    return "";
  }

  // Cleanup allocations.
  std::string result(buffer);
  free(buffer);
  return result;
}

std::string stringFromCFData(const CFDataRef& cf_data) {
  CFRange range = CFRangeMake(0, CFDataGetLength(cf_data));
  char* buffer = (char*)malloc(range.length + 1);
  memset(buffer, 0, range.length + 1);

  CFDataGetBytes(cf_data, range, (UInt8*)buffer);
  for (CFIndex i = 0; i < range.length; ++i) {
    if (buffer[i] == 0) {
      buffer[i] = ' ';
    }
  }

  // Cleanup allocations.
  std::string result(buffer);
  free(buffer);
  return result;
}

std::string stringFromCFNumber(const CFDataRef& cf_number) {
  unsigned int value;
  if (CFGetTypeID(cf_number) != CFNumberGetTypeID() ||
      !CFNumberGetValue((CFNumberRef)cf_number, kCFNumberIntType, &value)) {
    return "0";
  }

  // Cast as a string.
  return boost::lexical_cast<std::string>(value);
}
}
