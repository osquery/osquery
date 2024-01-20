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
#include <osquery/utils/darwin/system_profiler.h>

namespace osquery {
namespace tables {

QueryData genConnectedDisplays(QueryContext& context) {
  QueryData results;
  @autoreleasepool {
    Row r;

    NSDictionary* __autoreleasing result;
    Status status = getSystemProfilerReport("SPDisplaysDataType", result);
    if (!status.ok()) {
      LOG(ERROR) << "Failed to get connected displays: " << status.getMessage();
      return results;
    }

    NSDictionary* report = [[result objectForKey:@"_items"] lastObject];
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
  }
  return results;
} // context
} // namespace tables
} // namespace osquery
