/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#import <AppKit/NSDocument.h>
#import <Foundation/Foundation.h>

#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>

@interface SPDocument : NSDocument {
}
- (id)reportForDataType:(id)arg1;
@end

namespace osquery {
namespace tables {

QueryData genConnectedDisplays(QueryContext& context) {
  QueryData results;
  @autoreleasepool {
    Row r;

    // BEWARE: Because of the dynamic nature of the calls in this function, we
    // must be careful to properly clean up the memory. Any future modifications
    // to this function should attempt to ensure there are no leaks.
    CFURLRef bundle_url = CFURLCreateWithFileSystemPath(
        kCFAllocatorDefault,
        CFSTR("/System/Library/PrivateFrameworks/SPSupport.framework"),
        kCFURLPOSIXPathStyle,
        true);

    if (bundle_url == nullptr) {
      LOG(INFO) << "Error parsing SPSupport bundle URL";
      return results;
    }

    CFBundleRef bundle = CFBundleCreate(kCFAllocatorDefault, bundle_url);
    CFRelease(bundle_url);
    if (bundle == nullptr) {
      LOG(INFO) << "Error opening SPSupport bundle";
      return results;
    }

    CFBundleLoadExecutable(bundle);

    std::function<void()> cleanup = [&]() {
      CFBundleUnloadExecutable(bundle);
      CFRelease(bundle);
    };

#pragma clang diagnostic push
// We are silencing here because we don't know the selector beforehand
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"

    id cls = NSClassFromString(@"SPDocument");
    if (cls == nullptr) {
      LOG(INFO) << "Could not load SPDocument class";
      cleanup();

      return results;
    }

    SEL sel = @selector(new);
    if (![cls respondsToSelector:sel]) {
      LOG(INFO) << "SPDocument does not respond to new selector";
      cleanup();

      return results;
    }

    id document = [cls performSelector:sel];
    if (document == nullptr) {
      LOG(INFO) << "[SPDocument new] returned null";
      cleanup();

      return results;
    }

#pragma clang diagnostic pop

    cleanup = [&]() {
      CFRelease((__bridge CFTypeRef)document);
      CFBundleUnloadExecutable(bundle);
      CFRelease(bundle);
    };

    NSDictionary* report = [[[document reportForDataType:@"SPDisplaysDataType"]
        objectForKey:@"_items"] lastObject];
    NSArray* data = [report valueForKeyPath:@"spdisplays_ndrvs"];

    for (NSString* obj in data) {
      Row r;

      if (data == nullptr) {
        return results;
      }

      if ([obj valueForKey:@"_name"]) {
        r["name"] = SQL_TEXT([[obj valueForKey:@"_name"] UTF8String]);
      }

      if ([obj valueForKey:@"_spdisplays_display-product-id"]) {
        r["product_id"] = SQL_TEXT(
            [[obj valueForKey:@"_spdisplays_display-product-id"] UTF8String]);
      }

      if ([obj valueForKey:@"_spdisplays_display-serial-number"]) {
        r["serial_number"] = SQL_TEXT([[obj
            valueForKey:@"_spdisplays_display-serial-number"] UTF8String]);
      }

      if ([obj valueForKey:@"_spdisplays_display-vendor-id"]) {
        r["vendor_id"] = SQL_TEXT(
            [[obj valueForKey:@"_spdisplays_display-vendor-id"] UTF8String]);
      }

      if ([obj valueForKey:@"_spdisplays_display-week"]) {
        r["manufactured_week"] =
            INTEGER([[obj valueForKey:@"_spdisplays_display-week"] intValue]);
      } else {
        r["manufactured_week"] = INTEGER(-1);
      }

      if ([obj valueForKey:@"_spdisplays_display-year"]) {
        r["manufactured_year"] =
            SQL_TEXT([[obj valueForKey:@"_spdisplays_display-year"] intValue]);
      } else {
        r["manufactured_year"] = INTEGER(-1);
      }

      if ([obj valueForKey:@"_spdisplays_displayID"]) {
        r["display_id"] =
            SQL_TEXT([[obj valueForKey:@"_spdisplays_displayID"] UTF8String]);
      }

      if ([obj valueForKey:@"_spdisplays_pixels"]) {
        r["pixels"] =
            SQL_TEXT([[obj valueForKey:@"_spdisplays_pixels"] UTF8String]);
      }

      if ([obj valueForKey:@"_spdisplays_resolution"]) {
        r["resolution"] =
            SQL_TEXT([[obj valueForKey:@"_spdisplays_resolution"] UTF8String]);
      }

      if (NSString* ambient_brightness_enabled =
              [obj valueForKey:@"spdisplays_ambient_brightness_enabled"]) {
        if ([ambient_brightness_enabled isEqualToString:@"spdisplays_yes"]) {
          r["ambient_brightness_enabled"] = INTEGER(1);
        }
        if ([ambient_brightness_enabled isEqualToString:@"spdisplays_no"]) {
          r["ambient_brightness_enabled"] = INTEGER(0);
        }
      } else {
        r["ambient_brightness_enabled"] = INTEGER(-1);
      }

      if ([obj valueForKey:@"spdisplays_connection_type"]) {
        r["connection_type"] = SQL_TEXT(
            [[obj valueForKey:@"spdisplays_connection_type"] UTF8String]);
      }

      if ([obj valueForKey:@"spdisplays_display_type"]) {
        r["display_type"] =
            SQL_TEXT([[obj valueForKey:@"spdisplays_display_type"] UTF8String]);
      }

      if (NSString* main = [obj valueForKey:@"spdisplays_main"]) {
        if ([main isEqualToString:@"spdisplays_yes"]) {
          r["main"] = INTEGER(1);
        }
      } else {
        r["main"] = INTEGER(0);
      }

      if (NSString* mirror = [obj valueForKey:@"spdisplays_mirror"]) {
        if ([mirror isEqualToString:@"spdisplays_on"]) {
          r["mirror"] = INTEGER(1);
        } else {
          r["mirror"] = INTEGER(0);
        }
      }

      if (NSString* online = [obj valueForKey:@"spdisplays_online"]) {
        if ([online isEqualToString:@"spdisplays_yes"]) {
          r["online"] = INTEGER(1);
        } else {
          r["online"] = INTEGER(0);
        }
      }

      if (NSString* rotation = [obj valueForKey:@"spdisplays_rotation"]) {
        if ([rotation isEqualToString:@"spdisplays_supported"]) {
          r["rotation"] = INTEGER(1);
        } else {
          r["rotation"] = INTEGER(0);
        }
      } else {
        r["rotation"] = INTEGER(0);
      }

      results.push_back(r);
    }

    cleanup();
  }
  return results;
} // context
} // namespace tables
} // namespace osquery
