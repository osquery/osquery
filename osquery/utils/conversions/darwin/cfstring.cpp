/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed in accordance with the terms specified in
 *  the LICENSE file found in the root directory of this source tree.
 */

#include "cfstring.h"

namespace osquery {

std::string stringFromCFString(const CFStringRef& cf_string) {
  // Access, then convert the CFString. CFStringGetCStringPtr is less-safe.
  auto const wlength = CFStringGetLength(cf_string);
  auto const length =
      CFStringGetMaximumSizeForEncoding(wlength, kCFStringEncodingUTF8);
  if (length == kCFNotFound) {
    return "";
  }
  auto result = std::string(length + 1, '\0');
  // According to documentation: "if there is an error in conversion, the buffer
  // contains only partial results". And because of that we don't need to check
  // up the return value.
  CFStringGetCString(
      cf_string, &result.front(), result.size(), kCFStringEncodingUTF8);
  result.resize(result.find('\0'));
  return result;
}

}
