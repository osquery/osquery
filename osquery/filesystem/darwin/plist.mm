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

#include <boost/filesystem/path.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <glog/logging.h>

#import <Foundation/Foundation.h>

#include <osquery/filesystem.h>

namespace pt = boost::property_tree;

namespace osquery {

NSMutableArray* filterArray(id dataStructure);
NSMutableDictionary* filterDictionary(id dataStructure);

NSMutableDictionary* filterDictionary(id dataStructure) {
  @autoreleasepool {
    NSMutableDictionary* result = [NSMutableDictionary new];
    for (id key in [dataStructure allKeys]) {
      id klass = [[dataStructure objectForKey:key] class];
      NSString* className = NSStringFromClass(klass);
      if ([className isEqualToString:@"__NSArrayI"] ||
          [className isEqualToString:@"__NSArrayM"] ||
          [className isEqualToString:@"__NSCFArray"]) {
        [result setObject:filterArray([dataStructure objectForKey:key])
                   forKey:key];
      } else if ([className isEqualToString:@"__NSCFDictionary"]) {
        [result setObject:filterDictionary([dataStructure objectForKey:key])
                   forKey:key];
      } else if ([className isEqualToString:@"__NSCFData"]) {
        id data = [dataStructure objectForKey:key];
        NSString* dataString = [data base64EncodedStringWithOptions:0];
        [result setObject:dataString forKey:key];
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
      NSString* className = NSStringFromClass([value class]);
      if ([className isEqualToString:@"__NSCFDictionary"]) {
        [result addObject:filterDictionary(value)];
      } else if ([className isEqualToString:@"__NSArrayI"] ||
                 [className isEqualToString:@"__NSArrayM"] ||
                 [className isEqualToString:@"__NSCFArray"]) {
        [result addObject:filterArray(value)];
      } else if ([className isEqualToString:@"__NSCFData"]) {
        id data = [dataStructure objectForKey:value];
        NSString* dataString = [data base64EncodedStringWithOptions:0];
        [result addObject:dataString];
      } else {
        [result addObject:value];
      }
    }
    return result;
  }
}

NSMutableDictionary* filterPlist(NSData* plist) {
  @autoreleasepool {
    NSString* className = NSStringFromClass([plist class]);
    if ([className isEqualToString:@"__NSCFDictionary"]) {
      return filterDictionary((NSMutableDictionary*)plist);
    } else {
      NSMutableDictionary* result = [NSMutableDictionary new];
      [result setObject:filterArray((NSMutableArray*)plist) forKey:@"root"];
      return result;
    }
  }
}

Status parsePlistContent(const std::string& fileContent, pt::ptree& tree) {
  @autoreleasepool {
    int statusCode = 0;
    std::string statusString = "OK";

    std::stringstream ss;
    std::string jsonStringCxx;
    NSString* jsonStringObjc;
    NSData* jsonDataObjc;

    NSData* plistContent =
        [NSData dataWithBytes:fileContent.c_str() length:fileContent.size()];

    NSError* error = nil;
    NSMutableDictionary* plist;
    NSPropertyListFormat plistFormat;
    id plistData = [NSPropertyListSerialization
        propertyListWithData:plistContent
                     options:NSPropertyListImmutable
                      format:&plistFormat
                       error:&error];

    if (plistData == nil) {
      std::string errorMessage([[error localizedFailureReason] UTF8String]);
      LOG(ERROR) << errorMessage;
      statusCode = 1;
      statusString = errorMessage;
      goto cleanup;
    } else {
      switch (plistFormat) {
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
    }

    try {
      plist = filterPlist(plistData);
    } catch (const std::exception& e) {
      LOG(ERROR)
          << "An exception occurred while filtering the plist: " << e.what();
      statusCode = 1;
      statusString = e.what();
      goto cleanup;
    }

    if ([NSJSONSerialization isValidJSONObject:plist]) {
      jsonDataObjc =
          [NSJSONSerialization dataWithJSONObject:plist options:0 error:&error];
    } else {
      statusCode = 1;
      statusString = "Valid JSON was not deserialized";
      goto cleanup;
    }
    if (jsonDataObjc == nil) {
      std::string errorMessage([[error localizedFailureReason] UTF8String]);
      LOG(ERROR) << errorMessage;
      statusCode = 1;
      statusString = errorMessage;
      goto cleanup;
    }

    jsonStringObjc = [[NSString alloc] initWithBytes:[jsonDataObjc bytes]
                                              length:[jsonDataObjc length]
                                            encoding:NSUTF8StringEncoding];
    jsonStringCxx = std::string([jsonStringObjc UTF8String]);
    ss << jsonStringCxx;
    try {
      pt::read_json(ss, tree);
    } catch (pt::json_parser::json_parser_error& e) {
      LOG(ERROR) << "Error reading JSON: " << e.what();
      statusCode = 1;
      statusString = e.what();
      goto cleanup;
    }

  cleanup:
    return Status(statusCode, statusString);
  }
}

Status parsePlist(const boost::filesystem::path& path, pt::ptree& tree) {
  std::string fileContent;
  Status s = readFile(path, fileContent);
  if (!s.ok()) {
    return s;
  }
  return parsePlistContent(fileContent, tree);
}
}
