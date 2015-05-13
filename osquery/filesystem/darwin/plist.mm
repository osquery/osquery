/*
 *  Copyright (c) 2014, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under the BSD-style license found in the
 *  LICENSE file in the root directory of this source tree. An additional grant
 *  of patent rights can be found in the PATENTS file in the same directory.
 *
 */

#include <sstream>

#import <Foundation/Foundation.h>

#include <boost/filesystem/path.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <osquery/filesystem.h>
#include <osquery/logger.h>

namespace pt = boost::property_tree;

namespace osquery {

NSMutableArray* filterArray(id dataStructure);
NSMutableDictionary* filterDictionary(id dataStructure);

NSMutableDictionary* filterDictionary(id dataStructure) {
  @autoreleasepool {
    NSMutableDictionary* result = [NSMutableDictionary new];
    for (id key in [dataStructure allKeys]) {
      id value = [dataStructure objectForKey:key];
      if ([value isKindOfClass:[NSArray class]]) {
        [result setObject:filterArray([dataStructure objectForKey:key])
                   forKey:key];
      } else if ([value isKindOfClass:[NSDictionary class]]) {
        [result setObject:filterDictionary([dataStructure objectForKey:key])
                   forKey:key];
      } else if ([value isKindOfClass:[NSData class]]) {
        NSString* dataString = [value base64EncodedStringWithOptions:0];
        [result setObject:dataString forKey:key];
      } else if ([value isKindOfClass:[NSDate class]]) {
        NSNumber* seconds =
            [[NSNumber alloc] initWithDouble:[value timeIntervalSince1970]];
        [result setObject:seconds forKey:key];
      } else {
        [result setObject:[dataStructure objectForKey:key] forKey:key];
      }
    }
    return result;
  }
}

NSMutableArray* filterArray(id dataStructure) {
  @autoreleasepool {
    NSMutableArray* result = [NSMutableArray new];
    for (id value in dataStructure) {
      if ([value isKindOfClass:[NSDictionary class]]) {
        [result addObject:filterDictionary(value)];
      } else if ([value isKindOfClass:[NSArray class]]) {
        [result addObject:filterArray(value)];
      } else if ([value isKindOfClass:[NSData class]]) {
        NSString* dataString = [value base64EncodedStringWithOptions:0];
        [result addObject:dataString];
      } else if ([value isKindOfClass:[NSDate class]]) {
        NSNumber* seconds =
            [[NSNumber alloc] initWithDouble:[value timeIntervalSince1970]];
        [result addObject:seconds];
      } else {
        [result addObject:value];
      }
    }
    return result;
  }
}

NSMutableDictionary* filterPlist(NSData* plist) {
  @autoreleasepool {
    if ([plist isKindOfClass:[NSDictionary class]]) {
      return filterDictionary((NSMutableDictionary*)plist);
    } else {
      NSMutableDictionary* result = [NSMutableDictionary new];
      [result setObject:filterArray((NSMutableArray*)plist) forKey:@"root"];
      return result;
    }
  }
}

Status parsePlistContent(const std::string& content, pt::ptree& tree) {
  @autoreleasepool {
    NSData* plist_content =
        [NSData dataWithBytes:content.c_str() length:content.size()];

    // Read file content into a data object, containing potential plist data.
    NSError* error = nil;
    NSPropertyListFormat plist_format;
    id plist_data = [NSPropertyListSerialization
        propertyListWithData:plist_content
                     options:NSPropertyListImmutable
                      format:&plist_format
                       error:&error];
    if (plist_data == nil) {
      std::string error_message([[error localizedFailureReason] UTF8String]);
      VLOG(1) << error_message;
      return Status(1, error_message);
    }

    // Print a helpful verbose message based on the plist data's format.
    switch (plist_format) {
    case NSPropertyListOpenStepFormat:
      VLOG(1) << "plist was in openstep format";
      break;
    case NSPropertyListXMLFormat_v1_0:
      VLOG(1) << "plist was in xml format";
      break;
    case NSPropertyListBinaryFormat_v1_0:
      VLOG(1) << "plist was in binary format";
      break;
    default:
      VLOG(1) << "plist was in unknown format";
      break;
    }

    // Parse the plist data into a core foundation dictionary-literal.
    NSMutableDictionary* plist;
    try {
      plist = filterPlist(plist_data);
    } catch (const std::exception& e) {
      LOG(ERROR) << "Exception occurred while filtering plist: " << e.what();
      return Status(1, e.what());
    }

    // Convert the dictionary type into a JSON literal.
    NSData* json_data;
    if ([NSJSONSerialization isValidJSONObject:plist]) {
      json_data =
          [NSJSONSerialization dataWithJSONObject:plist options:0 error:&error];
    } else {
      return Status(1, "Valid JSON was not deserialized");
    }
    if (json_data == nil) {
      std::string error_message([[error localizedFailureReason] UTF8String]);
      LOG(ERROR) << error_message;
      return Status(1, error_message);
    }

    // Convert the JSON literal into a standard string.
    std::string json_string =
        [[[NSString alloc] initWithBytes:[json_data bytes]
                                  length:[json_data length]
                                encoding:NSUTF8StringEncoding] UTF8String];

    // Finally, parse the JSON blob into a property tree literal.
    try {
      std::stringstream json_stream;
      json_stream << json_string;
      pt::read_json(json_stream, tree);
    } catch (const pt::json_parser::json_parser_error& e) {
      LOG(ERROR) << "Error reading JSON: " << e.what();
      return Status(1, e.what());
    }
    return Status(0, "OK");
  }
}

Status parsePlist(const boost::filesystem::path& path, pt::ptree& tree) {
  std::string file_content;
  Status s = readFile(path, file_content);
  if (!s.ok()) {
    return s;
  }
  return parsePlistContent(file_content, tree);
}
}
