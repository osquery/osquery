/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include "cfdictionary.h"

#import <Foundation/Foundation.h>

namespace osquery {

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
    value = std::to_string(std::llround(unix_time));
  }

  return value;
}

Status serializeCFDictionaryToJSON(const CFDictionaryRef& dict,
                                   std::string& json) {
  if (dict == nullptr) {
    return Status(1, "Cannot serialize null CFDictionary");
  }

  @autoreleasepool {
    NSError* error = nil;
    NSData* jsonData =
        [NSJSONSerialization dataWithJSONObject:(__bridge NSDictionary*)dict
                                        options:0
                                          error:&error];
    if (error != nil || jsonData == nil) {
      return Status(
          1,
          "Failed to serialize policy parameters to JSON: " +
              (error ? std::string([[error localizedDescription] UTF8String])
                     : "unknown error"));
    }

    NSString* jsonString =
        [[NSString alloc] initWithData:jsonData encoding:NSUTF8StringEncoding];
    if (jsonString == nil) {
      return Status(1, "Failed to create string from JSON data");
    }

    json = stringFromCFString((__bridge CFStringRef)jsonString);
    return Status::success();
  }
}
} // namespace osquery
