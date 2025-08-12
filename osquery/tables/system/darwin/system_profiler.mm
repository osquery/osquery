/**
 * Copyright (c) 2014-present, The osquery authors
 *
 * This source code is licensed as defined by the LICENSE file found in the
 * root directory of this source tree.
 *
 * SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)
 */

#include <osquery/core/core.h>
#include <osquery/core/tables.h>
#include <osquery/logger/logger.h>
#include <osquery/utils/conversions/darwin/cfstring.h>
#include <osquery/utils/darwin/system_profiler.h>
#include <osquery/utils/json/json.h>

#include <Foundation/Foundation.h>

namespace osquery {
namespace tables {

id convertForJSON(id obj) {
  @try {
    if ([obj isKindOfClass:[NSDictionary class]]) {
      NSMutableDictionary* dict = [NSMutableDictionary
          dictionaryWithCapacity:[(NSDictionary*)obj count]];
      for (id key in (NSDictionary*)obj) {
        dict[key] = convertForJSON([(NSDictionary*)obj objectForKey:key]);
      }
      return dict;
    } else if ([obj isKindOfClass:[NSArray class]]) {
      NSMutableArray* arr =
          [NSMutableArray arrayWithCapacity:[(NSArray*)obj count]];
      for (id item in (NSArray*)obj) {
        [arr addObject:convertForJSON(item)];
      }
      return arr;
    } else if ([obj isKindOfClass:[NSDate class]]) {
      // formatter will be autoreleased when the pool is drained
      NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
      [formatter setDateFormat:@"yyyy-MM-dd'T'HH:mm:ssZ"];
      NSString* result = [formatter stringFromDate:(NSDate*)obj];
      return result;
    } else if ([obj isKindOfClass:[NSData class]]) {
      return [(NSData*)obj base64EncodedStringWithOptions:0];
    } else if ([obj isKindOfClass:[NSURL class]]) {
      return [(NSURL*)obj absoluteString];
    } else if ([obj isKindOfClass:[NSUUID class]]) {
      return [(NSUUID*)obj UUIDString];
    } else if ([obj isKindOfClass:[NSNumber class]] ||
               [obj isKindOfClass:[NSString class]]) {
      // These types are already JSON-safe
      return obj;
    } else {
      // For any other type, try to get a string representation
      return [obj description];
    }
  } @catch (NSException* exception) {
    LOG(WARNING) << "Exception in convertForJSON: "
                 << [[exception reason] UTF8String];
    return @"[Error converting object]";
  }
}

std::string objectToJson(id data) {
  @try {
    NSError* error = nil;
    id safeDict = convertForJSON(data);
    NSData* jsonData = [NSJSONSerialization dataWithJSONObject:safeDict
                                                       options:0
                                                         error:&error];
    if (error != nil || jsonData == nil) {
      LOG(WARNING) << "JSON serialization failed: "
                   << (error ? [[error localizedDescription] UTF8String]
                             : "unknown error");
      return "";
    }
    NSString* jsonString = [[NSString alloc] initWithData:jsonData
                                                 encoding:NSUTF8StringEncoding];
    if (jsonString == nil) {
      LOG(WARNING) << "Failed to create string from JSON data";
      return "";
    }
    return stringFromCFString((__bridge CFStringRef)jsonString);
  } @catch (NSException* exception) {
    LOG(WARNING) << "Exception in nsDictionaryToJson: "
                 << [[exception reason] UTF8String];
    return "";
  }
}

QueryData genSystemProfilerResults(QueryContext& context) {
  QueryData results;
  auto data_type_constraints = context.constraints["data_type"].getAll(EQUALS);

  @autoreleasepool {
    for (const auto& dataType : data_type_constraints) {
      NSDictionary* __autoreleasing report = nullptr;
      auto status = getSystemProfilerReport(dataType, report);

      if (!status.ok()) {
        LOG(WARNING) << "Failed to get system profiler report for " << dataType
                     << ": " << status.getMessage();
        continue;
      }

      if (report == nullptr) {
        LOG(WARNING) << "System profiler report is null for " << dataType;
        continue;
      }

      id items = [report objectForKey:@"_items"];
      if (items == nil) {
        LOG(WARNING) << "System profiler report items is null for " << dataType;
        continue;
      }

      Row r;
      r["data_type"] = dataType;
      r["value"] = objectToJson(items);
      results.push_back(r);
    }
  }

  return results;
}

} // namespace tables
} // namespace osquery