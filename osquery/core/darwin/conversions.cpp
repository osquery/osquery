 // Copyright 2004-present Facebook. All Rights Reserved.

#include <boost/lexical_cast.hpp>

#include "osquery/core/conversions.h"

namespace osquery {

std::string stringFromCFString(const CFStringRef cf_string) {
  CFIndex length;
  char *buffer;

  // Access, then convert the CFString. CFStringGetCStringPtr is less-safe.
  length = CFStringGetLength(cf_string);
  buffer = (char *)malloc(length + 1);
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
