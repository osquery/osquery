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
#include <Foundation/Foundation.h>
#include <Security/Security.h>

#include <osquery/core.h>
#include <osquery/filesystem.h>
#include <osquery/logger.h>
#include <osquery/tables.h>

#include "osquery/core/conversions.h"

#define DECLARE_TABLE_IMPLEMENTATION_authorizations
#include <generated/tables/tbl_authorizations_defs.hpp>
#define DECLARE_TABLE_IMPLEMENTATION_authorization_mechanisms
#include <generated/tables/tbl_authorization_mechanisms_defs.hpp>

namespace osquery {
namespace tables {

// Path to OS X authorizations cache.
#define AUTHORIZATION_FILE "/System/Library/Security/authorization.plist"

using authorizationCallback = std::function<void(NSString*)>;

void authorizations(QueryContext& context, authorizationCallback cb) {
  NSMutableArray* labels = nullptr;

  // Grab all labels
  if (context.constraints["label"].exists(EQUALS)) {
    labels = [[NSMutableArray alloc] init];
    auto label_values = context.constraints["label"].getAll(EQUALS);
    for (const auto& label : label_values) {
      [labels
          addObject:[NSString
                        stringWithCString:label.c_str()
                                 encoding:[NSString defaultCStringEncoding]]];
    }
  }

  if (labels == nullptr) {
    NSDictionary* authorization =
        [NSDictionary dictionaryWithContentsOfFile:@AUTHORIZATION_FILE];
    labels = [[NSMutableArray alloc]
        initWithArray:[authorization[@"rights"] allKeys]];
    [labels addObjectsFromArray:[authorization[@"rules"] allKeys]];
  }

  for (NSString* label in labels) {
    cb(label);
  }
}

QueryData genAuthorizationMechanisms(QueryContext& context) {
  QueryData results;

  @autoreleasepool {
    authorizations(
        context, ([&results](NSString* label) {
          CFDictionaryRef rights_ = nullptr;
          AuthorizationRightGet([label UTF8String], &rights_);
          if (rights_ == nullptr) {
            return;
          }

          Row r;
          NSDictionary* rights = (__bridge NSDictionary*)rights_;
          NSArray* mechs = [rights objectForKey:@"mechanisms"];
          if (mechs == nullptr) {
            CFRelease(rights_);
            return;
          }

          for (NSString* mech in mechs) {
            r["label"] = TEXT([label UTF8String]);
            r["privileged"] =
                ([mech rangeOfString:@"privileged"].location != NSNotFound)
                    ? "true"
                    : "false";
            r["entry"] = TEXT([mech UTF8String]);
            NSRange colon_loc = [mech rangeOfString:@":"];
            NSRange plugin_loc = NSMakeRange(0, colon_loc.location);
            NSRange mech_loc =
                NSMakeRange(colon_loc.location + 1,
                            [mech length] - (colon_loc.location + 1));
            r["plugin"] =
                TEXT([[mech substringWithRange:plugin_loc] UTF8String]);
            r["mechanism"] = TEXT([[[mech substringWithRange:mech_loc]
                stringByReplacingOccurrencesOfString:@",privileged"
                                          withString:@""] UTF8String]);
            results.push_back(r);
          }

          CFRelease(rights_);
        }));
  }
  return results;
}

QueryData genAuthorizations(QueryContext& context) {
  QueryData results;

  @autoreleasepool {
    authorizations(
        context, ([&results](NSString* label) {
          CFDictionaryRef rights = nullptr;
          AuthorizationRightGet([label UTF8String], &rights);
          if (rights == nullptr) {
            return;
          }

          CFIndex count = CFDictionaryGetCount(rights);
          std::vector<const void*> keys(count);
          std::vector<const void*> values(count);
          CFDictionaryGetKeysAndValues(rights, keys.data(), values.data());
          if (keys.data() == nullptr || values.data() == nullptr) {
            CFRelease(rights);
            return;
          }

          Row r;
          for (CFIndex i = 0; i < count; i++) {
            r["label"] = TEXT([label UTF8String]);
            id value = (__bridge id)values[i];
            auto key = [[(__bridge NSString*)keys[i]
                stringByReplacingOccurrencesOfString:@"-"
                                          withString:@"_"] UTF8String];

            if (CFGetTypeID(values[i]) == CFNumberGetTypeID()) {
              r[key] = TEXT([value intValue]);
            } else if (CFGetTypeID(values[i]) == CFStringGetTypeID()) {
              r[key] = TEXT([value UTF8String]);
            } else if (CFGetTypeID(values[i]) == CFBooleanGetTypeID()) {
              r[key] = TEXT(([value boolValue]) ? "true" : "false");
            }
          }

          results.push_back(r);
          CFRelease(rights);
        }));
  }

  return results;
}
}
}
