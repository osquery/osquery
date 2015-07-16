/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <Foundation/Foundation.h>
#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

namespace osquery {
namespace tables {

QueryData genAuthorizations(QueryContext &context) {
  @autoreleasepool {

    QueryData results;
    NSMutableArray *labelsNS;

    if (context.constraints["label"].exists(EQUALS)) {
      labelsNS = [[NSMutableArray alloc] init];
      auto labels = context.constraints["label"].getAll(EQUALS);
      for (const auto &label : labels) {
        [labelsNS
            addObject:[NSString
                          stringWithCString:label.c_str()
                                   encoding:[NSString defaultCStringEncoding]]];
      }
    }

    if (!labelsNS) {
      NSString *authorizationPlistPath =
          @"/System/Library/Security/authorization.plist";
      NSDictionary *authorizationDict =
          [NSDictionary dictionaryWithContentsOfFile:authorizationPlistPath];
      labelsNS = [[NSMutableArray alloc]
          initWithArray:[authorizationDict[@"rights"] allKeys]];
      [labelsNS addObjectsFromArray:[authorizationDict[@"rules"] allKeys]];
    }

    for (NSString *label in labelsNS) {
      Row r;
      CFDictionaryRef rightSet = nullptr;
      AuthorizationRightGet([label UTF8String], &rightSet);
      if (rightSet == nullptr) {
        continue;
      }

      CFIndex count = CFDictionaryGetCount(rightSet);
      const void *keys[count];
      const void *values[count];
      CFDictionaryGetKeysAndValues(rightSet, keys, values);

      for (CFIndex i = 0; i < count; i++) {
        r["label"] = TEXT([label UTF8String]);
        NSString *keyNS = (__bridge NSString *)keys[i];
        id valueNS = (__bridge id)values[i];
        if (CFGetTypeID(values[i]) == CFNumberGetTypeID()) {
          r[[[keyNS stringByReplacingOccurrencesOfString:@"-"
                                              withString:@"_"] UTF8String]] =
              TEXT([valueNS intValue]);
        } else if (CFGetTypeID(values[i]) == CFStringGetTypeID()) {
          r[[[keyNS stringByReplacingOccurrencesOfString:@"-"
                                              withString:@"_"] UTF8String]] =
              TEXT([valueNS UTF8String]);
        } else if (CFGetTypeID(values[i]) == CFBooleanGetTypeID()) {
          r[[[keyNS stringByReplacingOccurrencesOfString:@"-"
                                              withString:@"_"] UTF8String]] =
              TEXT(([valueNS boolValue]) ? "true" : "false");
        }
      }

      results.push_back(r);

      if (rightSet != nullptr) {
        CFRelease(rightSet);
      }
    }

    return results;
  }
}
}
}
